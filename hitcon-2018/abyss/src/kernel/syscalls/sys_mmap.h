#ifndef SYS_MMAP_H
#define SYS_MMAP_H

#include <mm/mmap.h>
#include <stdint.h>

#define MAP_FIXED 0x10

void *sys_mmap(
  void *addr, uint64_t len, int prot,
  int flags, int fd, uint64_t offset);

int sys_munmap(void *addr, uint64_t len) ;

/* alias */
#define sys_mprotect mprotect

#endif
