#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/types.h>

struct uint128_t {
	uint64_t lo;
	uint64_t hi;
};

/* This is a simple list with atomic push and pop
 * we use cmpxchg with 16 bytes to perform push and pop
 */
struct atomic_list {
	union {
		/* top is a pointer to the first element in list, NULL if empty
		 * transact is a incrementing counter which is used in order
		 * to identify uniquely any change in the list state.
		 */
		struct {
			struct list_head *top;
			long transact;
		};
		struct uint128_t raw;
	};
} __aligned(16);

/*
 * Global object with a pointer (top) to first element in list
 * This a list of free epc pages.
 */
volatile struct atomic_list freelist;

/*	the content of src is compared with cmp
 *	If the same: with and *mem are swapped, 1 is returned
 *	Otherwise: no swap performed, 0 is returned
 */
static inline char lock_cmpxchg16b(volatile struct uint128_t *src,
			struct uint128_t cmp, struct uint128_t with)
{
	char result;

	__asm__ __volatile__
	(
		"lock cmpxchg16b %1\n\t"
		"setz %0"
		: "=q" (result)
		, "+m" (*src)
		, "+d" (cmp.hi)
		, "+a" (cmp.lo)
		: "c" (with.hi)
		, "b" (with.lo)
		: "cc", "memory"
	);

	return result;
}

void _pool_push(struct list_head *item)
{
	struct atomic_list cmp, next;
	int ret;

	while (1) {
		cmp.raw = freelist.raw;
		next.raw = cmp.raw;
		next.transact++;
		next.top = item;
		item->next = cmp.top;
		ret = lock_cmpxchg16b(&freelist.raw, cmp.raw, next.raw);
		if (ret)
			return;
	}
}

struct list_head *_pool_pop(void)
{
	struct atomic_list cmp, next;
	struct list_head *p;
	int ret;

	while (1) {
		cmp.raw = freelist.raw;
		p = cmp.top;
		if (!p)
			return NULL;

		next.raw = cmp.raw;
		next.transact++;
		next.top = p->next;
		ret = lock_cmpxchg16b(&freelist.raw, cmp.raw, next.raw);
		if (ret)
			return p;
	}

	return NULL;
}

int _pool_init(void)
{
	BUILD_BUG_ON((sizeof(struct atomic_list) != 16));
	return 0;
}

int _pool_empty(void)
{
	return (freelist.top == NULL);
}

int _pool_check(void)
{
	struct list_head *p = freelist.top;
	int count = 0;

	while (p) {
		count++;
		p = p->next;
	}

	return 0;
}


