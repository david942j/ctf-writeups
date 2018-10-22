#include <hypercalls/hp_stat.h>
#include <mm/kmalloc.h>
#include <mm/translate.h>

int hp_fstat(int fildes, uint64_t phy_addr) {
  uint64_t *kbuf = kmalloc(sizeof(uint64_t) * 2, MALLOC_NO_ALIGN);
  kbuf[0] = fildes;
  kbuf[1] = phy_addr;
  int ret = hypercall(NR_HP_fstat, physical(kbuf));
  kfree(kbuf);
  return ret;
}
