#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <erl_nif.h>
#include "async_calls.h"
#include "os.h"

#include <stdio.h>

struct nif_file {
	struct ac_request_common ac_req;

	struct ac_request_common *nested_reqs_head;
	struct ac_request_common **nested_reqs_tail;

	file_fd_handle fd;
	unsigned sync:1;
	unsigned write_closed:1;
        unsigned ac_req_queued:1;
	int close_refcount:29;
	int free_refcount;
	int truncates_in_flight;
	ErlNifMutex *lock;
	int64_t safe_size;
	int64_t size;
};

struct nif_file_ref {
	struct nif_file *file;
	int closed;
};

static ErlNifResourceType *file_ref_res_type;
static struct ac_context *nif_ac_context;
static int64_t nif_file_count;
static int64_t nif_file_ref_count;
static int64_t common_req_count;


static
ERL_NIF_TERM make_error(ErlNifEnv *env, const char *error)
{
	return enif_make_tuple(env, 2,
			       enif_make_atom(env, "error"),
			       enif_make_atom(env, error));
}

static
ERL_NIF_TERM do_make_ref_LOCKED(ErlNifEnv *env,
				struct nif_file *file)
{
	struct nif_file_ref *ref = enif_alloc_resource(file_ref_res_type, sizeof(struct nif_file_ref));
	ERL_NIF_TERM rv;
	ref->file = file;
	file->close_refcount++;
	file->free_refcount++;
	ref->closed = 0;
	rv = enif_make_resource(env, ref);
	enif_release_resource(ref);
	__sync_add_and_fetch(&nif_file_ref_count, 1);
	return rv;
}

static
void submit_mutation_req_and_unlock(struct ac_request_common *req, struct nif_file *file);

static
void exec_file_requests(struct ac_request_common *file_req)
{
	struct nif_file *file = (struct nif_file *)file_req;
	struct ac_request_common *req;
	int new_free_refcount;

	while (1) {
		enif_mutex_lock(file->lock);
		req = ac_request_dequeue(&file->nested_reqs_head, &file->nested_reqs_tail);

		if (!req) {
			assert(file->ac_req_queued);
			file->ac_req_queued = 0;
			break;
		}

		enif_mutex_unlock(file->lock);

		req->proc(req);
	}

	new_free_refcount = --file->free_refcount;
	enif_mutex_unlock(file->lock);

	if (!new_free_refcount) {
		assert(file->close_refcount == 0);
		enif_mutex_destroy(file->lock);
		free(file);
	}
}

static
ERL_NIF_TERM nif_open(ErlNifEnv* env,
		      int argc,
		      const ERL_NIF_TERM argv[])
{
	int rv;
	ErlNifBinary name_binary;
	char namebuf[8192];
	int flags;
	int error;
	struct nif_file *file;

	rv = enif_inspect_binary(env, argv[0], &name_binary);
	if (!rv)
		return make_error(env, "name");
	if (name_binary.size > sizeof(namebuf) - 1)
		return make_error(env, "enametoolong");
	rv = enif_get_int(env, argv[1], &flags);
	if (!rv)
		return make_error(env, "flags");

	file = calloc(1, sizeof(struct nif_file));
	if (!file)
		return make_error(env, "enomem");
	__sync_add_and_fetch(&nif_file_count, 1);

	memcpy(namebuf, name_binary.data, name_binary.size);
	namebuf[name_binary.size] = 0;

	error = 0;
	file->fd = raw_file_open(namebuf, flags, &error);
	if (error) {
		__sync_add_and_fetch(&nif_file_count, -1);
		free(file);
		return make_error(env, raw_file_error_message(error));
	}

	file->ac_req.proc = exec_file_requests;
	file->ac_req.next = NULL;
	file->nested_reqs_head = NULL;
	file->nested_reqs_tail = &file->nested_reqs_head;

	rv = raw_file_size(file->fd, &file->size);
	if (rv) {
		raw_file_close(file->fd);
		free(file);
		return make_error(env, raw_file_error_message(error));
	}
	file->safe_size = file->size;

	file->lock = enif_mutex_create("file mutex");

	return enif_make_tuple(env, 2,
			       enif_make_atom(env, "ok"),
			       do_make_ref_LOCKED(env, file));
}

static
struct nif_file_ref *term2valid_locked_ref(ErlNifEnv *env, ERL_NIF_TERM term)
{
	int rv;
	struct nif_file_ref *ref;
	rv = enif_get_resource(env, term, file_ref_res_type, (void **)&ref);
	if (!rv)
		return NULL;
	enif_mutex_lock(ref->file->lock);
	if (ref->closed) {
		enif_mutex_unlock(ref->file->lock);
		return NULL;
	}
	return ref;
}

static
void do_close_inner_and_unlock(struct nif_file *file)
{
	int do_close = 0;
	file_fd_handle fd;
	if (!--file->close_refcount) {
		fd = file->fd;
		do_close = 1;
		file->fd = -1;
	}
	enif_mutex_unlock(file->lock);
	if (do_close)
		raw_file_close(fd); /* TODO: check return value maybe */
}

static
void file_ref_res_type_dtor(ErlNifEnv *env, void *_obj)
{
	struct nif_file_ref *ref = _obj;
	struct nif_file *file = ref->file;
	int new_free_refcount;

	enif_mutex_lock(file->lock);
	new_free_refcount = --file->free_refcount;
	if (!ref->closed) {
		fprintf(stderr, "Closing leaked unclosed fd (%p)\n", (void *)(file->fd));
		assert(!ref->closed);
		do_close_inner_and_unlock(file);
	} else
		enif_mutex_unlock(file->lock);
	if (!new_free_refcount) {
		assert(file->close_refcount == 0);
		enif_mutex_destroy(file->lock);
		free(file);
	}
}

static
ERL_NIF_TERM nif_dup(ErlNifEnv* env,
		     int argc,
		     const ERL_NIF_TERM argv[])
{
	struct nif_file_ref *ref;
	struct nif_file *file;
	ERL_NIF_TERM rv;
	ref = term2valid_locked_ref(env, argv[0]);
	if (!ref)
		return make_error(env, "badarg");
	file = ref->file;
	assert(file->close_refcount > 0);
	rv = do_make_ref_LOCKED(env, file);
	enif_mutex_unlock(file->lock);
	return enif_make_tuple(env, 2,
			       enif_make_atom(env, "ok"),
			       rv);
}

static
ERL_NIF_TERM nif_set_sync(ErlNifEnv* env,
			  int argc,
			  const ERL_NIF_TERM argv[])
{
	struct nif_file_ref *ref;
	int use_sync;

	if (!enif_get_int(env, argv[1], &use_sync))
		return make_error(env, "badarg");

	ref = term2valid_locked_ref(env, argv[0]);
	if (!ref)
		return make_error(env, "badarg");

	ref->file->sync = !!use_sync;

	enif_mutex_unlock(ref->file->lock);

	return enif_make_atom(env, "ok");
}

static
ERL_NIF_TERM nif_suppress_writes(ErlNifEnv* env,
				 int argc,
				 const ERL_NIF_TERM argv[])
{
	struct nif_file_ref *ref;

	ref = term2valid_locked_ref(env, argv[0]);
	if (!ref)
		return make_error(env, "badarg");

	ref->file->write_closed = 1;

	enif_mutex_unlock(ref->file->lock);

	return enif_make_atom(env, "ok");
}

struct common_req {
	struct ac_request_common ac_req;
	struct nif_file *file;
	ErlNifEnv *env;
	ErlNifPid reply_pid;
	ERL_NIF_TERM tag;
};

static
void submit_mutation_req(struct common_req *req)
{
	struct nif_file *file = req->file;
	enif_mutex_lock(file->lock);
	submit_mutation_req_and_unlock(&req->ac_req, file);
}

static
void submit_mutation_req_and_unlock(struct ac_request_common *ac_req, struct nif_file *file)
{
	unsigned queued = 0;
	if (!file->ac_req_queued) {
		assert(file->ac_req.next == NULL);
		queued = file->ac_req_queued = 1;
		file->free_refcount++;
	}
	ac_request_enqueue(ac_req, &file->nested_reqs_tail);
	enif_mutex_unlock(file->lock);

	if (queued) {
		assert(file->ac_req.next == NULL);
		ac_perform(nif_ac_context, &file->ac_req);
	}
}

static
void init_common_req_and_unlock(struct common_req *req,
				struct nif_file *file,
				ac_syscall_t proc,
				ErlNifEnv *env,
				ERL_NIF_TERM tag);

static
char *init_common_req(
	struct common_req *req,
	ac_syscall_t proc,
	ErlNifEnv *env,
	ERL_NIF_TERM tag, ERL_NIF_TERM ref_term)
{
	struct nif_file_ref *ref;
	struct nif_file *file;

	ref = term2valid_locked_ref(env, ref_term);
	if (!ref)
		return "badarg";

	file = ref->file;

	init_common_req_and_unlock(req, file, proc, env, tag);

	return NULL;
}

static
void init_common_req_and_unlock(
	struct common_req *req,
	struct nif_file *file,
	ac_syscall_t proc,
	ErlNifEnv *env,
	ERL_NIF_TERM tag)
{
	file->close_refcount++;
	file->free_refcount++;
	enif_mutex_unlock(file->lock);

	req->ac_req.proc = proc;
	req->ac_req.next = NULL;
	req->env = enif_alloc_env();
	req->file = file;
	enif_self(env, &req->reply_pid);
	req->tag = enif_make_copy(req->env, tag);
}

static
void free_req_common_and_unlock(struct common_req *c, struct nif_file *file);

static
void free_req_common(struct common_req *c)
{
	struct nif_file *file = c->file;
	enif_mutex_lock(file->lock);
	free_req_common_and_unlock(c, file);
}

static
void free_req_common_and_unlock(struct common_req *c, struct nif_file *file)
{
	int new_free_refcount;
	assert(c->ac_req.next == NULL);

	new_free_refcount = --file->free_refcount;
	do_close_inner_and_unlock(file);
	if (!new_free_refcount) {
		enif_mutex_destroy(file->lock);
		free(file);
	}

	enif_free_env(c->env);
	free(c);
	__sync_add_and_fetch(&common_req_count, -1);
}

struct pread_req {
	struct common_req c;

	volatile int *busy_wait_state_place;
	ErlNifUInt64 off;
	ErlNifBinary buf;
	int error;
};

#define BUSY_WAIT_WAITING 1
#define BUSY_WAIT_DONE 0

static
void perform_read_tail(struct pread_req *req);

static
void perform_read(struct ac_request_common *_req)
{
	struct pread_req *req = (struct pread_req *)_req;
	volatile int *busy_wait_state_place = req->busy_wait_state_place;
	struct nif_file *file;
	size_t readen;

	file = req->c.file;
	readen = req->buf.size;
	req->error = raw_file_pread(file->fd,
				    req->buf.data,
				    &readen,
				    (int64_t)(req->off));

	if (__builtin_expect(readen != req->buf.size, 0) && !req->error) {
		enif_realloc_binary(&req->buf, (size_t)readen);
	}

	if (__builtin_expect(
		    busy_wait_state_place
		    && __sync_bool_compare_and_swap(&req->busy_wait_state_place,
						    busy_wait_state_place, NULL), 1)) {
		/* we found that a) read is still waiting for
		 * us b) we managed to 'claim' completion
		 * before nif_read gave up waiting */
		/* we know nif_read is still waiting and it
		 * now owns completion of request */
		*busy_wait_state_place = BUSY_WAIT_DONE;
		__sync_synchronize();
		return;
	}

	/* otherwise either busy wait was not requested or given up
	 * already and we own completion of request */
	perform_read_tail(req);
}

static
void perform_read_tail(struct pread_req *req)
{
	ERL_NIF_TERM reply_value;
	int error = req->error;

	if (error) {
		const char *error_str;

		enif_release_binary(&req->buf);

		error_str = raw_file_error_message(error);
		reply_value = enif_make_tuple(
			req->c.env, 2,
			enif_make_atom(req->c.env, "error"),
			enif_make_atom(req->c.env, error_str));
	} else {
		reply_value = enif_make_binary(req->c.env, &req->buf);
	}

	enif_send(0, &req->c.reply_pid, req->c.env,
		  enif_make_tuple(req->c.env, 2,
				  req->c.tag,
				  reply_value));
	free_req_common(&req->c);
}

static
ERL_NIF_TERM nif_pread(ErlNifEnv* env,
		       int argc,
		       const ERL_NIF_TERM argv[])
{
	struct pread_req *req;
	struct nif_file *file;
	ErlNifUInt64 off;
	uint len;
	int rv;
	char *err;
	int k;
	volatile int busy_wait_state;

	rv = enif_get_uint64(env, argv[2], &off);
	if (!rv)
		return make_error(env, "badarg");
	rv = enif_get_uint(env, argv[3], &len);
	if (!rv)
		return make_error(env, "badarg");

	req = calloc(1, sizeof(struct pread_req));
	if (!req)
		return make_error(env, "enomem");
	__sync_add_and_fetch(&common_req_count, 1);

	err = init_common_req(&req->c, perform_read, env, argv[0], argv[1]);
	if (err) {
		__sync_add_and_fetch(&common_req_count, -1);
		free(req);
		return make_error(env, err);
	}

	rv = enif_alloc_binary(len, &req->buf);
	if (!rv) {
		free_req_common(&req->c);
		return make_error(env, "enomem");
	}

	req->off = off;

	file = req->c.file;
	enif_mutex_lock(file->lock);

	if (off + len > file->safe_size) {
		submit_mutation_req_and_unlock(&req->c.ac_req, file);

		return argv[0];
	}


	enif_mutex_unlock(file->lock);

	if (__builtin_expect(req->c.file->sync, 0)) {
 		ac_sync_perform(&req->c.ac_req);
		return argv[0];
	}

	busy_wait_state = BUSY_WAIT_WAITING;
	req->busy_wait_state_place = &busy_wait_state;

	ac_perform(nif_ac_context, &req->c.ac_req);

	k = 20000;
	do {
		__asm__ __volatile__("pause");
		if (!--k)
			goto wait_timedout;
	} while (busy_wait_state != BUSY_WAIT_DONE);

	if (__builtin_expect(!req->error, 1)) {
		ERL_NIF_TERM retval;
		/* this is our fast path. If read was
		 * successful, we skip sending result
		 * back. We directly return it instead. */
		retval = enif_make_binary(env, &req->buf);
		free_req_common(&req->c);
		return retval;
	}

	perform_read_tail(req);
	return argv[0];

wait_timedout:

	/* we've exhausted our wait quota. We stop
	 * waiting but we need to handle possible race
	 * of completing request now and potentially
	 * run completion. */

	if (!__sync_bool_compare_and_swap(&req->busy_wait_state_place,
					  &busy_wait_state, NULL)) {

		/* ok so our busy waiting actually succeed */
		perform_read_tail(req);

		/* if we failed to 'free' busy_wait_state place, then
		 * perform_read is done and is about to mutate
		 * busy_wait_state to DONE. We need to wait that,
		 * otherwise returning from nif_read will invalidate
		 * busy_wait_state's memory and cause perform_read to
		 * 'shit' to that unowned place */

		while (busy_wait_state != BUSY_WAIT_DONE) {
			__asm__ __volatile__("pause");
		}
	}

	/* we succeeded in 'releasing'
	 * busy_wait_state place. perform_read
	 * now owns 'completion' of read (and
	 * freeing of req) */
	return argv[0];

}

struct append_req {
	struct common_req c;

	int64_t size;
	ErlNifBinary bin;
	ERL_NIF_TERM data;
};

void perform_append(struct ac_request_common *_req)
{
	struct append_req *req = (struct append_req *)_req;
	struct nif_file *file;
	size_t written;
	int rv;
	ERL_NIF_TERM reply_value = req->c.tag;

	file = req->c.file;

	written = (size_t)(req->bin.size);
	rv = raw_file_write(file->fd, req->bin.data, &written);

	if (rv) {
		abort();
		/*
                 * const char *error_str = raw_file_error_message(rv);
		 * reply_value = enif_make_atom(req->c.env, error_str);
                 */
	}

	if (!enif_is_empty_list(req->c.env, req->c.tag))
		enif_send(0, &req->c.reply_pid, req->c.env,
			  enif_make_tuple(req->c.env, 3,
					  req->c.tag,
					  enif_make_uint(req->c.env, (unsigned int)written),
					  reply_value));

	enif_mutex_lock(file->lock);
	if (!file->truncates_in_flight) {
		/* but see abort above */
		assert(file->safe_size + written == req->size);
		file->safe_size = req->size;
	}
	free_req_common_and_unlock(&req->c, file);
}

static
ERL_NIF_TERM nif_append(ErlNifEnv* env,
			int argc,
			const ERL_NIF_TERM argv[])
{
	struct append_req *req;
	struct nif_file *file;
	char *err;
	int rv;
	int fast_write;

	req = calloc(1, sizeof(struct append_req));
	if (!req)
		return make_error(env, "enomem");
	__sync_add_and_fetch(&common_req_count, 1);

	err = init_common_req(&req->c, perform_append, env, argv[0], argv[1]);
	if (err) {
		__sync_add_and_fetch(&common_req_count, -1);
		free(req);
		return make_error(env, err);
	}

	if (req->c.file->write_closed) {
		free_req_common(&req->c);
		return make_error(env, "write_closed");
	}

	req->data = enif_make_copy(req->c.env, argv[2]);
	rv = enif_inspect_iolist_as_binary(req->c.env, req->data, &req->bin);
	if (!rv) {
		free_req_common(&req->c);
		return make_error(env, "badarg");
	}

	file = req->c.file;
	fast_write = 0;
	enif_mutex_lock(file->lock);

	req->size = req->c.file->size += req->bin.size;

	if (file->free_refcount <= 100) {
		req->c.tag = enif_make_list(req->c.env, 0);
		fast_write = 1;
	}

	submit_mutation_req_and_unlock(&req->c.ac_req, file);

	return fast_write ? enif_make_list(env, 0) : argv[0];
}

static
void perform_close(struct ac_request_common *_req)
{
	struct common_req *req = (struct common_req *)_req;
	enif_mutex_lock(req->file->lock);
	/* we're supposed to be executed from exec_file_requests which
	 * should keep one free_refcount reference */
	assert(req->file->free_refcount > 0);
	do_close_inner_and_unlock(req->file);

	enif_send(0, &req->reply_pid, req->env,
		  enif_make_tuple(req->env, 2,
				  req->tag,
				  enif_make_atom(req->env, "ok")));

	free_req_common(req);
}

static
ERL_NIF_TERM nif_initiate_close(ErlNifEnv* env,
				int argc,
				const ERL_NIF_TERM argv[])
{
	struct nif_file_ref *ref;
	struct nif_file *file;
	struct common_req *req;

	req = calloc(1, sizeof(struct common_req));
	if (!req)
		return make_error(env, "enomem");

	__sync_add_and_fetch(&common_req_count, 1);

	ref = term2valid_locked_ref(env, argv[1]);
	if (!ref) {
		free(ref);
		__sync_add_and_fetch(&common_req_count, -1);
		return make_error(env, "badarg");
	}

	file = ref->file;

	ref->closed = 1;

	init_common_req_and_unlock(req, file, perform_close, env, argv[0]);

	submit_mutation_req(req);

	return argv[0];
}

static
void perform_fsync(struct ac_request_common *_req)
{
	struct common_req *req = (struct common_req *)_req;
	ERL_NIF_TERM reply_value = req->tag;
	int error;

	error = raw_file_fsync(req->file->fd);
	if (error) {
		const char *error_str = raw_file_error_message(error);
		reply_value = enif_make_atom(req->env, error_str);
	}

	enif_send(0, &req->reply_pid, req->env,
		  enif_make_tuple(req->env, 2,
				  req->tag,
				  reply_value));

	free_req_common(req);
}

static
ERL_NIF_TERM nif_fsync(ErlNifEnv* env,
		       int argc,
		       const ERL_NIF_TERM argv[])
{
	struct common_req *req;
	char *err;

	req = calloc(1, sizeof(struct common_req));
	if (!req)
		return make_error(env, "enomem");

	__sync_add_and_fetch(&common_req_count, 1);

	err = init_common_req(req, perform_fsync, env, argv[0], argv[1]);

	if (err) {
		__sync_add_and_fetch(&common_req_count, -1);
		free(req);
		return make_error(env, err);
	}

	submit_mutation_req(req);

	return argv[0];
}

static
ERL_NIF_TERM nif_size(ErlNifEnv* env,
		      int argc,
		      const ERL_NIF_TERM argv[])
{
	struct nif_file_ref *ref;
	int64_t size;

	ref = term2valid_locked_ref(env, argv[0]);
	if (!ref)
		return make_error(env, "badarg");

	size = ref->file->size;
	enif_mutex_unlock(ref->file->lock);

	return enif_make_tuple(env, 2,
			       enif_make_atom(env, "ok"),
			       enif_make_int64(env, size));
}

struct truncate_req {
	struct common_req c;

	int64_t pos;
};

static
void perform_truncate(struct ac_request_common *_req)
{
	struct truncate_req *req = (struct truncate_req *)_req;

	struct nif_file *file;
	int rv;
	ERL_NIF_TERM reply_value = req->c.tag;
	int truncates_in_flight;

	file = req->c.file;

	rv = raw_file_truncate(file->fd, req->pos);
	if (rv) {
		abort();
	}

	enif_send(0, &req->c.reply_pid, req->c.env,
		  enif_make_tuple(req->c.env, 2,
				  req->c.tag,
				  reply_value));

	enif_mutex_lock(file->lock);
	truncates_in_flight = --file->truncates_in_flight;
	if (!truncates_in_flight)
		file->safe_size = req->pos;
	free_req_common_and_unlock(&req->c, file);
}

static
ERL_NIF_TERM nif_truncate(ErlNifEnv* env,
			  int argc,
			  const ERL_NIF_TERM argv[])
{
	struct truncate_req *req;
	struct nif_file *file;
	int64_t size;
	char *err;

	if (!enif_get_int64(env, argv[2], &size))
		return make_error(env, "badarg");

	req = calloc(1, sizeof(struct truncate_req));
	if (!req)
		return make_error(env, "enomem");
	__sync_add_and_fetch(&common_req_count, 1);

	err = init_common_req(&req->c, perform_truncate, env, argv[0], argv[1]);
	if (err) {
		__sync_add_and_fetch(&common_req_count, -1);
		free(req);
		return make_error(env, err);
	}

	req->pos = size;

	file = req->c.file;
	enif_mutex_lock(file->lock);

	file->size = size;
	if (file->safe_size > size)
		file->safe_size = size;

	file->truncates_in_flight++;

	submit_mutation_req_and_unlock(&req->c.ac_req, file);

	return argv[0];
}

static ErlNifFunc nif_functions[] = {
	{"do_open", 2, nif_open},
	{"initiate_close", 2, nif_initiate_close},
	{"dup", 1, nif_dup},
	{"set_sync", 2, nif_set_sync},
	{"suppress_writes", 1, nif_suppress_writes},
	{"initiate_pread", 4, nif_pread},
	{"initiate_append", 3, nif_append},
	{"initiate_fsync", 2, nif_fsync},
	{"file_size", 1, nif_size},
	{"initiate_truncate", 3, nif_truncate}
};

static
int on_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info)
{
	file_ref_res_type = enif_open_resource_type(env, "raw_file_io", "file_ref_res_type", file_ref_res_type_dtor, ERL_NIF_RT_CREATE, 0);
	if (file_ref_res_type == NULL)
		return 1;
	nif_ac_context = ac_create(16);
	return nif_ac_context == NULL;
}

static
int on_upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM info)
{
	return 0;
}

ERL_NIF_INIT(raw_file_io, nif_functions, &on_load, NULL, &on_upgrade, NULL)
