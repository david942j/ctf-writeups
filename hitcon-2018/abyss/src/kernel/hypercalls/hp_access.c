#include <hypercalls/hp_access.h>
#include <mm/kmalloc.h>
#include <mm/translate.h>

int hp_access(uint32_t paddr, int mode) {
  uint64_t *kbuf = kmalloc(sizeof(int) * 2, MALLOC_NO_ALIGN);
  kbuf[0] = paddr;
  kbuf[1] = mode;
  int ret = hypercall(NR_HP_access, physical(kbuf));
  kfree(kbuf);
  return ret;
}
