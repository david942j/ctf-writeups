#ifndef MMAP_H
#define MMAP_H

#include <stdint.h>

extern uint64_t brk_end;

void *mmap(void *addr, uint64_t len, int prot);
int mprotect(void *addr, uint64_t len, int prot);

#endif
