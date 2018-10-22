#include <hypercalls/hp_stat.h>
#include <mm/kmalloc.h>
#include <mm/translate.h>
#include <mm/uaccess.h>
#include <syscalls/sys_stat.h>
#include <utils/errno.h>
#include <utils/string.h>

int sys_fstat(int fildes, struct stat *buf) {
  if(!access_ok(VERIFY_WRITE, buf, sizeof(struct stat))) return -EFAULT;

  void *dst = kmalloc(sizeof(struct stat), MALLOC_NO_ALIGN);
  int ret = hp_fstat(fildes, physical(dst));
  if(ret == 0) memcpy(buf, dst, sizeof(struct stat));
  kfree(dst);
  return ret;
}
