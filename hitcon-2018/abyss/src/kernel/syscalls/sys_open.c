#include <hypercalls/hp_access.h>
#include <hypercalls/hp_open.h>
#include <mm/kmalloc.h>
#include <mm/translate.h>
#include <mm/uaccess.h>
#include <syscalls/sys_open.h>
#include <utils/errno.h>
#include <utils/string.h>

int sys_open(const char *path) {
  if(!access_string_ok(path)) return -EFAULT;
  void *dst = copy_str_from_user(path);
  if(dst == 0) return -ENOMEM;

  /* do whitelist here */
  if(!(
#define OK(str) strcmp(dst, #str) == 0
      OK(ld.so.2) ||
      /* OK(/lib64/ld-linux-x86-64.so.2) || */
      /* OK(libc.so.6) || */
      /* OK(./bc.so.6) || */
      OK(/lib/x86_64-linux-gnu/libc.so.6) ||
      OK(/proc/sys/kernel/osrelease) ||
      OK(/etc/ld.so.cache) ||
      OK(./user.elf) ||
      /* OK(/bin/cat) || */
      OK(flag)
#undef OK
      )) return -ENOENT;

  int fd = hp_open(physical(dst));
  kfree(dst);
  return fd;
}

int sys_openat(int fildes, const char *path) {
  /* only supports fd == AT_FDCWD */
  if(fildes != AT_FDCWD) return -EINVAL;
  return sys_open(path);
}

int sys_access(const char *path, int mode) {
  if(!access_string_ok(path)) return -EFAULT;
  void *dst = copy_str_from_user(path);
  if(dst == 0) return -ENOMEM;
  int ret = hp_access(physical(dst), mode);
  kfree(dst);
  return ret;
}
