#ifndef SYSCALL_HANDLER_H
#define SYSCALL_HANDLER_H

#include <stdint.h>

#include <syscalls/sys_brk.h>
#include <syscalls/sys_close.h>
#include <syscalls/sys_execve.h>
#include <syscalls/sys_exit.h>
#include <syscalls/sys_mmap.h>
#include <syscalls/sys_open.h>
#include <syscalls/sys_prctl.h>
#include <syscalls/sys_read.h>
#include <syscalls/sys_stat.h>
#include <syscalls/sys_write.h>

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_fstat 5
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_brk 12
#define SYS_writev 20
#define SYS_access 21
#define SYS_execve 59
#define SYS_exit 60
#define SYS_arch_prctl 158
#define SYS_fadvise64 221
#define SYS_exit_group 231
#define SYS_openat 257

#define MAX_SYS_NR 257

static int ZERO(void) { return 0; }
/* nop */
#define sys_fadvise64 ZERO

uint64_t syscall_handler(uint64_t arg0, uint64_t arg1, uint64_t arg2,
  uint64_t arg3, uint64_t arg4, uint64_t arg5);

#endif
