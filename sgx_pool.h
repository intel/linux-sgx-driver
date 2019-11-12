#ifndef __INTEL_SGX_POOL_H__
#define __INTEL_SGX_POOL_H__

#include <linux/types.h>

struct list_head *_pool_pop(void);
void _pool_push(struct list_head *item);
int _pool_init(void);
int _pool_empty(void);
int _pool_check(void);

#endif
