#ifndef ASYNC_CALLS_H
#define ASYNC_CALLS_H

#include <stdint.h>

struct ac_context;
struct ac_request_common;

typedef void (*ac_syscall_t)(struct ac_request_common *req);

struct ac_context *ac_create(int threads);

struct ac_request_common {
	struct ac_request_common *next;
	ac_syscall_t proc;
};

static inline
void ac_request_enqueue(struct ac_request_common *req,
			struct ac_request_common ***tail)
{
	**tail = req;
	*tail = &req->next;
}

static inline
struct ac_request_common *ac_request_dequeue(struct ac_request_common **head,
					     struct ac_request_common ***tail)
{
	struct ac_request_common *req = *head;
	if (!req)
		return req;
	if (!(*head = req->next))
		*tail = head;
	req->next = NULL;
	return req;
}

void ac_perform(struct ac_context *ac,
		struct ac_request_common *req);

static inline
void ac_sync_perform(struct ac_request_common *req) {
	req->proc(req);
}


#endif
