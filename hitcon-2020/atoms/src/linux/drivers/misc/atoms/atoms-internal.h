/*
 * Internal common interfaces for ATOMS.
 *
 * Copyright (c) 2020 david942j
 */
#ifndef _ATOMS_INTERNAL_H
#define _ATOMS_INTERNAL_H

#include <linux/spinlock.h>

// #define DAVID942J

#ifdef DAVID942J
 #define debug(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
 #define debug(...)
#endif /* DAVID942j */

struct atoms_mem *atoms_mem_create_or_find_by_token(unsigned long long token);
struct atoms_mem *atoms_mem_get(struct atoms_mem *mem);
void atoms_mem_put(struct atoms_mem *mem);
void atoms_mem_info(struct atoms_mem *mem, unsigned long long *ptoken,
                    size_t *ppages, size_t *psegs);
int atoms_mem_alloc(struct atoms_mem *mem, size_t size, size_t *poffset);
struct page *atoms_mem_page_at(struct atoms_mem *mem, size_t off);
void atoms_mem_remove_from_pool(struct atoms_mem *mem);

#endif /* _ATOMS_INTERNAL_H */
