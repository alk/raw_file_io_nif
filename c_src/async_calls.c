#include <erl_nif.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>

#include "async_calls.h"
#include "guasi_dlists.h"

struct ac_context {
	struct dlist_head requests;
	ErlNifMutex *lock;
	ErlNifCond *cond;
	int shutdown;
	int threads;
	ErlNifTid thread_ids[1];
};

struct ac_req {
	struct dlist_head link;
	void *priv;
	ac_syscall_t proc;
	ac_cleanup_t free;
};

static void *ac_thread(void *data);
static void do_ac_free(struct ac_context *c, int threads);

struct ac_context *ac_create(int threads)
{
	int i;
	struct ac_context *ptr = calloc(1, offsetof(struct ac_context, thread_ids) + threads * sizeof(ErlNifTid));
	dlist_init_head(&ptr->requests);
	ptr->lock = enif_mutex_create("ac lock");
	ptr->cond = enif_cond_create("ac cond");
	ptr->threads = threads;

	for (i = 0; i < threads; i++) {
		int rv = enif_thread_create("ac thread", &(ptr->thread_ids[i]), ac_thread, ptr, 0);
		if (rv < 0) {
			do_ac_free(ptr, i);
			return NULL;
		}
	}

	return ptr;
}

void ac_submit(struct ac_context *c,
	       void *priv,
	       ac_syscall_t proc,
	       ac_cleanup_t free)
{
	struct ac_req *req;

	req = calloc(1, sizeof(struct ac_req));
	req->priv = priv;
	req->proc = proc;
	req->free = free;

	enif_mutex_lock(c->lock);
	dlist_addt(&req->link, &c->requests);
	enif_cond_signal(c->cond);
	enif_mutex_unlock(c->lock);
}

static
void free_request(struct ac_req *req, int is_shutdown)
{
	if (req->free)
		req->free(req->priv, is_shutdown);
	free(req);
}


static void *ac_thread(void *data)
{
	struct ac_context *c = data;
	enif_mutex_lock(c->lock);
	while (!c->shutdown) {
		struct dlist_head *lh = dlist_first(&c->requests);
		struct ac_req *req;

		if (!lh) {
			enif_cond_wait(c->cond, c->lock);
			continue;
		}

		dlist_del(lh);

		enif_mutex_unlock(c->lock);

		req = DLIST_ENTRY(lh, struct ac_req, link);
		req->proc(req->priv);
		free_request(req, 0);

		enif_mutex_lock(c->lock);
	}
	enif_mutex_unlock(c->lock);
	return 0;
}

void ac_free(struct ac_context *c)
{
	do_ac_free(c, c->threads);
}

static
void do_ac_free(struct ac_context *c, int threads)
{
	enif_mutex_lock(c->lock);
	c->shutdown = 1;
	enif_cond_broadcast(c->cond);
	enif_mutex_unlock(c->lock);

	while (--threads >= 0)
		enif_thread_join(c->thread_ids[threads], 0);

	{
		struct dlist_head *lh;
		while ((lh = dlist_first(&c->requests)) != NULL) {
			struct ac_req *req = DLIST_ENTRY(lh, struct ac_req, link);
			free_request(req, 1);
		}
	}

	enif_mutex_destroy(c->lock);
	enif_cond_destroy(c->cond);
}
