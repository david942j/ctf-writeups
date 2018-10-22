#include <mm/translate.h>
#include <syscalls/syscall_handler.h>
#include <utils/errno.h>

static const void* syscall_table[MAX_SYS_NR + 1] = {
#define ENTRY(f) [SYS_##f]=sys_##f

  ENTRY(read),
  ENTRY(write),
  ENTRY(open),
  ENTRY(close),
  ENTRY(fstat),
  ENTRY(mmap),
  ENTRY(mprotect),
  ENTRY(munmap),
  ENTRY(brk),
  ENTRY(writev),
  ENTRY(access),
  /* ENTRY(execve), */
  ENTRY(exit),
  ENTRY(arch_prctl),
  ENTRY(fadvise64),
  ENTRY(exit_group),
  ENTRY(openat),

#undef ENTRY
};

/* #define DEBUG */

#ifdef DEBUG

#include <hypercalls/hp_write.h>
#include <utils/string.h>
#include <mm/kmalloc.h>

void dump_val(uint64_t ret) {
  static char kbuf[30];
  uint64_t tmp = ret;
  if(tmp == 0) memcpy(kbuf, "0x0\x00", 4);
  else {
    int cur = 0;
    kbuf[cur++] = '0'; kbuf[cur++] = 'x';
    for(int i=15;i>=0;i--) {
      int z = (tmp >> (i * 4)) & 0xf;
      if(z == 0 && cur == 2) continue;
      if(z < 10) kbuf[cur++] = z + '0';
      else kbuf[cur++] = z - 10 + 'a';
    }
    kbuf[cur] = 0;
  }
  hp_write(2, physical(kbuf), strlen(kbuf));
}

#endif

uint64_t syscall_handler(
  uint64_t arg0, uint64_t arg1, uint64_t arg2,
  uint64_t arg3, uint64_t arg4, uint64_t arg5) {

  uint32_t nr;
  asm("mov %[nr], eax;"
    : [nr] "=r"(nr)
    );
#ifdef DEBUG

  char *sys = 0;
  switch(nr) {
  case 0: sys = "read"; break;
  case 1: sys = "write"; break;
  case 2: sys = "open"; break;
  case 3: sys = "close"; break;
  case 5: sys = "fstat"; break;
  case 9: sys = "mmap"; break;
  case 10: sys = "mprotect"; break;
  case 11: sys = "munmap"; break;
  case 12: sys = "brk"; break;
  case 20: sys = "writev"; break;
  case 21: sys = "access"; break;
  case 59: sys = "execve"; break;
  case 60: sys = "exit"; break;
  case 63: sys = "[not implemented] uname"; break;
  case 158: sys = "arch_prctl"; break;
  case 221: sys = "fadvise64"; break;
  case 231: sys = "exit_group"; break;
  case 257: sys = "openat"; break;
  default: sys = "unsupported";
  }
  hp_write(2, physical(sys), strlen(sys));
  hp_write(2, physical("("), 1);
  if(strcmp(sys, "unsupported") == 0) { dump_val(nr); hp_write(2, physical(")\n"), 2); }
#endif
  if(nr > MAX_SYS_NR || syscall_table[nr] == 0)
    return -ENOSYS;
  void *fptr = (void*) ((uint64_t) syscall_table[nr] | KERNEL_BASE_OFFSET);
  uint64_t ret = ((uint64_t(*)(
        uint64_t, uint64_t, uint64_t,
        uint64_t, uint64_t, uint64_t)) fptr)(
    arg0, arg1, arg2,
    arg3, arg4, arg5
    );
#ifdef DEBUG
  dump_val(arg0);
  hp_write(2, physical(", "), 2);
  dump_val(arg1);
  hp_write(2, physical(", "), 2);
  dump_val(arg2);
  hp_write(2, physical(") = "), 4);
  dump_val(ret);
  hp_write(2, physical("\n"), 1);
#endif
  return ret;
}
