/*
 *  guasi by Davide Libenzi (generic userspace async syscall implementation)
 *  Copyright (C) 2003  Davide Libenzi
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#if !defined(_GUASI_DLISTS_H)
#define _GUASI_DLISTS_H


#define DLIST_ENTRY(p, t, m) ((t *)((char *)(p) - (unsigned long)(&((t *) 0)->m)))


struct dlist_head {
	struct dlist_head *next, *prev;
};



static inline void dlist_init_head(struct dlist_head *p) {

	p->prev = p->next = p;
}

static inline void dlist_del(struct dlist_head *p) {
	struct dlist_head *prev = p->prev, *next = p->next;

	next->prev = prev;
	prev->next = next;
}

static inline void dlist_add(struct dlist_head *itm,
			     struct dlist_head *prev,
			     struct dlist_head *next) {

	next->prev = itm;
	itm->next = next;
	itm->prev = prev;
	prev->next = itm;
}

static inline void dlist_addh(struct dlist_head *itm, struct dlist_head *head) {

	dlist_add(itm, head, head->next);
}

static inline void dlist_addt(struct dlist_head *itm, struct dlist_head *head) {

	dlist_add(itm, head->prev, head);
}

static inline void dlist_splice(struct dlist_head *list, struct dlist_head *head) {
	struct dlist_head *first = list->next;

	if (first != list) {
		struct dlist_head *last = list->prev;
		struct dlist_head *at = head->next;
		first->prev = head;
		head->next = first;
		last->next = at;
		at->prev = last;
	}
}

static inline struct dlist_head *dlist_first(struct dlist_head *head) {

	return head->next != head ? head->next: NULL;
}

static inline struct dlist_head *dlist_next(struct dlist_head *itm,
					    struct dlist_head *head) {

	return itm->next != head ? itm->next: NULL;
}

static inline struct dlist_head *dlist_last(struct dlist_head *head) {

	return head->prev != head ? head->prev: NULL;
}

static inline struct dlist_head *dlist_prev(struct dlist_head *itm,
					    struct dlist_head *head) {

	return itm->prev != head ? itm->prev: NULL;
}


#endif

