#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <erl_nif.h>
#include "async_calls.h"
#include "os.h"

#include <stdio.h>

struct nif_file {
	file_fd_handle fd;
	int close_refcount;
	int free_refcount;
	ErlNifMutex *lock;
};

struct nif_file_ref {
	struct nif_file *file;
	int closed;
};

static ErlNifResourceType *file_ref_res_type;
static struct ac_context *nif_ac_context;

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
	return rv;
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

	memcpy(namebuf, name_binary.data, name_binary.size);
	namebuf[name_binary.size] = 0;

	error = 0;
	file->fd = raw_file_open(namebuf, flags, &error);
	if (error) {
		free(file);
		return make_error(env, raw_file_error_message(error));
	}

	file->lock = enif_mutex_create("file mutex");

	return do_make_ref_LOCKED(env, file);
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
ERL_NIF_TERM nif_close(ErlNifEnv* env,
		       int argc,
		       const ERL_NIF_TERM argv[])
{
	struct nif_file_ref *ref = term2valid_locked_ref(env, argv[0]);
	if (!ref)
		return make_error(env, "badarg");
	ref->closed = 1;
	do_close_inner_and_unlock(ref->file);
	return enif_make_atom(env, "ok");
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
	return rv;
}

struct common_req {
	struct nif_file *file;
	ErlNifEnv *env;
	ErlNifPid reply_pid;
	ERL_NIF_TERM tag;
};

static
char *init_common_req(
	struct common_req *req,
	ErlNifEnv *env,
	ERL_NIF_TERM tag, ERL_NIF_TERM ref_term)
{
	struct nif_file_ref *ref;
	struct nif_file *file;

	req->env = enif_alloc_env();

	ref = term2valid_locked_ref(env, ref_term);
	if (!ref) {
		enif_free_env(req->env);
		return "badarg";
	}
	file = ref->file;
	file->close_refcount++;
	file->free_refcount++;
	enif_mutex_unlock(file->lock);

	req->file = file;
	enif_self(env, &req->reply_pid);
	req->tag = enif_make_copy(req->env, tag);

	return NULL;
}

static
void free_req_common(struct common_req *c)
{
	int new_free_refcount;
	struct nif_file *file = c->file;

	enif_mutex_lock(file->lock);
	new_free_refcount = --file->free_refcount;
	do_close_inner_and_unlock(file);
	if (!new_free_refcount) {
		enif_mutex_destroy(file->lock);
		free(file);
	}

	enif_free_env(c->env);
	free(c);
}

struct pread_req {
	struct common_req c;

	ErlNifUInt64 off;
	ErlNifBinary buf;
};

static
void perform_read(void *_req)
{
	struct pread_req *req = _req;
	struct nif_file *file;
	ERL_NIF_TERM reply_value;
	size_t readen;
	int error;

	file = req->c.file;
	readen = req->buf.size;
	error = raw_file_pread(file->fd,
			       req->buf.data,
			       &readen,
			       (int64_t)(req->off));
	if (error) {
		const char *error_str = raw_file_error_message(error);
		reply_value = enif_make_tuple(
			req->c.env, 2,
			enif_make_atom(req->c.env, "error"),
			enif_make_atom(req->c.env, error_str));
		enif_release_binary(&req->buf);
	} else {
		enif_realloc_binary(&req->buf, (size_t)readen);
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
	ErlNifUInt64 off;
	uint len;
	int rv;
	char *err;

	rv = enif_get_uint64(env, argv[2], &off);
	if (!rv)
		return make_error(env, "badarg");
	rv = enif_get_uint(env, argv[3], &len);
	if (!rv)
		return make_error(env, "badarg");

	req = calloc(1, sizeof(struct pread_req));
	if (!req)
		return make_error(env, "enomem");

	err = init_common_req(&req->c, env, argv[0], argv[1]);
	if (err) {
		free(req);
		return make_error(env, err);
	}

	rv = enif_alloc_binary(len, &req->buf);
	if (!rv) {
		free_req_common(&req->c);
		return make_error(env, "enomem");
	}

	req->off = off;

	ac_submit(nif_ac_context, req, perform_read, 0);

	return argv[0];
}

struct append_req {
	struct common_req c;

	ERL_NIF_TERM data;
};

void perform_append(void *_req)
{
	struct append_req *req = _req;
	struct nif_file *file;
	ErlNifBinary bin;
	size_t written;
	int rv;
	ERL_NIF_TERM reply_value = req->c.tag;

	file = req->c.file;
	rv = enif_inspect_iolist_as_binary(req->c.env, req->data, &bin);
	if (!rv) {
		reply_value = enif_make_atom(req->c.env, "badarg");
		goto after_write;
	}

	written = (size_t)bin.size;
	rv = raw_file_write(file->fd, bin.data, &written);

	if (rv) {
		const char *error_str = raw_file_error_message(rv);
		reply_value = enif_make_atom(req->c.env, error_str);
	}

after_write:

	enif_send(0, &req->c.reply_pid, req->c.env,
		  enif_make_tuple(req->c.env, 3,
				  req->c.tag,
				  enif_make_uint(req->c.env, (unsigned int)written),
				  reply_value));

	free_req_common(&req->c);
}

static
ERL_NIF_TERM nif_append(ErlNifEnv* env,
			int argc,
			const ERL_NIF_TERM argv[])
{
	struct append_req *req;
	char *err;

	req = calloc(1, sizeof(struct append_req));
	if (!req)
		return make_error(env, "enomem");

	err = init_common_req(&req->c, env, argv[0], argv[1]);
	if (err) {
		free(req);
		return make_error(env, err);
	}

	req->data = enif_make_copy(req->c.env, argv[2]);

	ac_submit(nif_ac_context, req, perform_append, 0);

	return argv[0];
}


static
ERL_NIF_TERM do_nothing(ErlNifEnv* env,
			int argc,
			const ERL_NIF_TERM argv[])
{
	return enif_make_atom(env, "nif");
}


static ErlNifFunc nif_functions[] = {
	{"do_nothing", 1, do_nothing},
	{"do_open", 2, nif_open},
	{"close", 1, nif_close},
	{"dup", 1, nif_dup},
	{"initiate_pread", 4, nif_pread},
	{"initiate_append", 3, nif_append}
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
