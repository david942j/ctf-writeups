/*
 * Memory management of ATOMS.
 *
 * Copyright (c) 2020 david942j
 */

#include <linux/mm.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include "atoms-internal.h"

#define MAX_NUM_SEGMENTS 16
struct atoms_mem {
  unsigned long long token;
  refcount_t refcount;
  spinlock_t seg_lock;
  struct {
    void *addr;
    size_t size; // page shifted
  } segments[MAX_NUM_SEGMENTS];
};

/* just too lazy to use an RB tree.. use an array instead */
#define MAX_NUM_MEM 16
static DEFINE_SPINLOCK(pool_lock);
static struct atoms_mem *pool[MAX_NUM_MEM];

static struct atoms_mem *atoms_mem_create(unsigned long long token)
{
  struct atoms_mem *mem = kzalloc(sizeof(*mem), GFP_KERNEL);

  if (!mem)
    return NULL;
  mem->token = token;
  /* atoms_mem_get() */
  refcount_set(&mem->refcount, 1);
  spin_lock_init(&mem->seg_lock);
  return mem;
}

struct atoms_mem *atoms_mem_create_or_find_by_token(unsigned long long token)
{
  int i;
  struct atoms_mem *ret = NULL;

  spin_lock(&pool_lock);
  for (i = 0; i < MAX_NUM_MEM; i++)
    if (pool[i] && pool[i]->token == token) {
      ret = atoms_mem_get(pool[i]);
      break;
    }
  if (!ret) {
    for (i = 0; i < MAX_NUM_MEM; i++)
      if (!pool[i])
        break;
    if (i < MAX_NUM_MEM) {
      pool[i] = atoms_mem_create(token);
      ret = atoms_mem_get(pool[i]);
    }
  }
  spin_unlock(&pool_lock);
  return ret;
}

struct atoms_mem *atoms_mem_get(struct atoms_mem *mem)
{
  refcount_inc(&mem->refcount);
  return mem;
}

void atoms_mem_put(struct atoms_mem *mem)
{
  if (!mem)
    return;

  if (refcount_dec_and_test(&mem->refcount)) {
    int i;

    debug("freeing mem with token 0x%llx", mem->token);
    for (i = 0; i < MAX_NUM_SEGMENTS; i++)
      if (mem->segments[i].addr)
        vfree(mem->segments[i].addr);
    kfree(mem);
  } else debug("0x%llx has refcount = %u", mem->token, refcount_read(&mem->refcount));
}

void atoms_mem_info(struct atoms_mem *mem, unsigned long long *ptoken,
                    size_t *ppages, size_t *psegs)
{
  int i;
  size_t pages = 0;

  *ptoken = mem->token;
  for (i = 0; i < MAX_NUM_SEGMENTS; i++) {
    if (!mem->segments[i].addr)
      break;
    else
      pages += mem->segments[i].size;
  }
  *ppages = pages;
  *psegs = i;
}

int atoms_mem_alloc(struct atoms_mem *mem, size_t size, size_t *poffset)
{
  int i;
  int ret = 0;
  void *addr;
  size_t off = 0;

  if ((size & 0xfff) || size > 16 * PAGE_SIZE)
    return -EINVAL;
  addr = vmalloc_user(size);
  if (!addr)
    return -ENOMEM;
  spin_lock(&mem->seg_lock);
  for (i = 0; i < MAX_NUM_SEGMENTS; i++)
    if (!mem->segments[i].addr)
      break;
    else
      off += mem->segments[i].size;
  if (i == MAX_NUM_SEGMENTS) {
    ret = -ENOSPC;
    vfree(addr);
    goto out;
  }
  mem->segments[i].addr = addr;
  mem->segments[i].size = size >> PAGE_SHIFT;
  *poffset = off << PAGE_SHIFT;
out:
  spin_unlock(&mem->seg_lock);
  return ret;
}

struct page *atoms_mem_page_at(struct atoms_mem *mem, size_t off)
{
  int i;
  size_t now = 0;

  spin_lock(&mem->seg_lock);
  for (i = 0; i < MAX_NUM_SEGMENTS; i++)
    if (!mem->segments[i].addr) break;
    else {
      if (now <= off && off < now + mem->segments[i].size) {
        spin_unlock(&mem->seg_lock);
        debug("fetching page @ 0x%lx000 from 0x%llx, found at seg[%d]", off, mem->token, i);
        return vmalloc_to_page(mem->segments[i].addr + ((off - now) << PAGE_SHIFT));
      }
      now += mem->segments[i].size;
    }
  spin_unlock(&mem->seg_lock);
  return NULL;
}

void atoms_mem_remove_from_pool(struct atoms_mem *mem)
{
  int i;

  spin_lock(&pool_lock);
  for (i = 0; i < MAX_NUM_MEM; i++)
    if (pool[i] == mem) {
      atoms_mem_put(pool[i]);
      pool[i] = NULL;
      break;
    }
  spin_unlock(&pool_lock);
}
