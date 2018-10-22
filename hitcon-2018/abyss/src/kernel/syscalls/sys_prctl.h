#ifndef SYS_PRCTL_H
#define SYS_PRCTL_H

#define ARCH_SET_FS 0x1002

#define MSR_FS_BASE 0xc0000100

int sys_arch_prctl(int code, uint64_t *addr);

#endif
