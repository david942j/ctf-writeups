#include <mm/translate.h>
#include <syscalls/sys_brk.h>
#include <utils/errno.h>
#include <utils/misc.h>

void *sys_brk(const void *addr_) {
  uint64_t addr = alignup(addr_);
  if(addr == 0) return (void*) brk_end;
  if(!USER_MEM_RANGE_OK(addr)) return (void*) -EACCES;
  if(addr < brk_end) return (void*) -ENOMEM;

  /* mmap for it */
  void *ret = mmap((void*) brk_end, addr - brk_end, PROT_RW);
  if((int64_t) ret == 0) return (void*) -ENOMEM;
  brk_end = addr;
  return (void*) brk_end;
}
