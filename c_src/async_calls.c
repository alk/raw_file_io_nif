#include <erl_nif.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <assert.h>

#include <sys/eventfd.h>

#include "async_calls.h"

/* everything is serialized through ac_context lock. But we attempt to
 * have lifo order of thread wakeups. I.e. if there's no load all the
 * time same thread(s) are used.
 *
 * Thus waiting threads are organized in lifo order in waiting_threads
 * field of ac_context. When thread is given request, it's passed in
 * req field of thread. When all threads are busy requests are put
 * into requests list in ac_context. And thread always considers
 * global list before going to bed.
 *
 * Such "deliberate unfairness" of wakeups seems to improve
 * performance a bit by waking same thread(s) all the time. Maybe just
 * in my silly microbenchmark. Perhaps due to cache effects.
 */
struct ac_thread {
	struct ac_thread *next;
	int evfd;
	struct ac_request_common *req;
};

struct ac_context {
	struct ac_thread *waiting_threads;
	struct ac_request_common *requests_head;
	struct ac_request_common **requests_tail;
	ErlNifMutex *lock;
	int shutdown;
	int threads;
	ErlNifTid thread_ids[1];
};

static void *ac_thread(void *data);
static void do_ac_free(struct ac_context *c, int threads);

struct ac_context *ac_create(int threads)
{
	int i;
	struct ac_context *ptr = calloc(1, offsetof(struct ac_context, thread_ids) + threads * sizeof(ErlNifTid));
	ptr->requests_head = 0;
	ptr->requests_tail = &ptr->requests_head;
	ptr->lock = enif_mutex_create("ac lock");
	ptr->threads = threads;
	ptr->waiting_threads = NULL;

	for (i = 0; i < threads; i++) {
		int rv = enif_thread_create("ac thread", &(ptr->thread_ids[i]), ac_thread, ptr, 0);
		if (rv < 0) {
			do_ac_free(ptr, i);
			return NULL;
		}
	}

	return ptr;
}

void ac_perform(struct ac_context *c,
		struct ac_request_common *req)
{
	struct ac_thread *thread;

	req->next = NULL;

	enif_mutex_lock(c->lock);
	if ((thread = c->waiting_threads)) {
		c->waiting_threads = thread->next;
		assert(thread->req == NULL);
		thread->next = NULL;
		thread->req = req;
		enif_mutex_unlock(c->lock);
		eventfd_write(thread->evfd, 1);
	} else {
		/* everybody is busy. use global list and there's no
		 * one to wake up */
		ac_request_enqueue(req, &c->requests_tail);
		enif_mutex_unlock(c->lock);
	}
}

#define CMM_ACCESS_ONCE(x)	(*(__volatile__  __typeof__(x) *)&(x))
#define	cmm_barrier()	__asm__ __volatile__ ("" : : : "memory")

static void *ac_thread(void *data)
{
	struct ac_context *c = data;
	struct ac_thread self;
	self.evfd = eventfd(0, 0);
	self.req = NULL;
	self.next = NULL;
	enif_mutex_lock(c->lock);
	while (!c->shutdown) {
		struct ac_request_common *req;

		req = self.req;
		if (req)
			goto have_req;

		/* if we don't have personal request, consider global
		 * list */
		req = ac_request_dequeue(&c->requests_head, &c->requests_tail);

		if (!req) {
			eventfd_t dummy;
			int k;
			if (!self.next) {
				self.next = c->waiting_threads;
				c->waiting_threads = &self;
			}
			enif_mutex_unlock(c->lock);

			k = 500;
			while (CMM_ACCESS_ONCE(c->waiting_threads) == &self && --k) {
				__asm__ __volatile__("pause");
			}

			while (!CMM_ACCESS_ONCE(self.req))
				eventfd_read(self.evfd, &dummy);

			enif_mutex_lock(c->lock);
			continue;
		}

	have_req:
		self.req = NULL;
		enif_mutex_unlock(c->lock);

		req->proc(req);

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
	/* TODO */
	/* nif doesn't need this anyways */
	abort();
}
