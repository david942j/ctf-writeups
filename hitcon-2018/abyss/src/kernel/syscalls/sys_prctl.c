#include <mm/uaccess.h>
#include <syscalls/sys_prctl.h>
#include <utils/errno.h>

static void set_fs(uint64_t* addr) {
  asm(
    "mov rdx, %[addr];"
    "mov eax, edx;"
    "shr rdx, 32;"
    "mov ecx, %[msr_index];"
    "wrmsr;"
    ::[addr]"r"(addr), [msr_index]"i"(MSR_FS_BASE)
    : "rdx", "rax", "rcx"
  );
}

int sys_arch_prctl(int code, uint64_t* addr) {
  if(code != ARCH_SET_FS) return -EINVAL;
  if(code == ARCH_SET_FS) {
    if(!access_ok(VERIFY_READ, addr, 8)) return -EFAULT;
    set_fs(addr);
    return 0;
  }
  return -EINVAL;
}
