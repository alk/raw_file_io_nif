#ifndef ASYNC_CALLS_H
#define ASYNC_CALLS_H

#include <stdint.h>

struct ac_context;

typedef void (*ac_syscall_t)(void *);
typedef void (*ac_cleanup_t)(void *, int is_shutdown);

struct ac_context *ac_create(int threads);
void ac_free(struct ac_context *);

void ac_submit(struct ac_context *c, void *priv, ac_syscall_t proc, ac_cleanup_t free);



#endif
