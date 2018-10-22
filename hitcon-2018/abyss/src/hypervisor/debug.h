#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG

#include <assert.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <sys/ioctl.h>

#define debug(...) fprintf(stderr, __VA_ARGS__)
#define dump_segment_register(n, s) \
  debug("%3s base=0x%016llx limit=%08x selector=%04x " \
    "type=0x%02x dpl=%d db=%d l=%d g=%d avl=%d\n", \
    (n), (s)->base, (s)->limit, (s)->selector, \
    (s)->type, (s)->dpl, (s)->db, (s)->l, (s)->g, (s)->avl)

#define dump_dtable(n, s) \
  debug("%3s base=%016llx limit=%04x \n", (n), (s)->base, (s)->limit)

void dump_regs(int vcpufd) {
  struct kvm_regs regs;
  assert(ioctl(vcpufd, KVM_GET_REGS, &regs) == 0);

  debug("\nDump regs\n");
  debug("rax\t0x%016llx rbx\t0x%016llx rcx\t0x%016llx rdx\t0x%016llx\n",
    regs.rax, regs.rbx, regs.rcx, regs.rdx);
  debug("rsp\t0x%016llx rbp\t0x%016llx rsi\t0x%016llx rdi\t0x%016llx\n",
    regs.rsp, regs.rbp, regs.rsi, regs.rdi);
  debug("rip\t0x%016llx r8\t0x%016llx r9\t0x%016llx r10\t0x%016llx\n",
    regs.rip, regs.r8, regs.r9, regs.r10);
  debug("r11\t0x%016llx r12\t0x%016llx r13\t0x%016llx r14\t0x%016llx\n",
    regs.r11, regs.r12, regs.r13, regs.r14);
  debug("r15\t0x%016llx rflags\t0x%08llx\n", regs.r15, regs.rflags);

  struct kvm_sregs sregs;
  assert(ioctl(vcpufd, KVM_GET_SREGS, &sregs) == 0);

  dump_segment_register("cs", &sregs.cs);
  dump_segment_register("ds", &sregs.ds);
  dump_segment_register("es", &sregs.es);
  dump_segment_register("ss", &sregs.ss);
  dump_segment_register("fs", &sregs.fs);
  dump_segment_register("gs", &sregs.gs);
  dump_segment_register("tr", &sregs.tr);

  dump_dtable("gdt", &sregs.gdt);
  dump_dtable("ldt", &sregs.ldt);

  debug("cr0\t0x%016llx\n", sregs.cr0);
  debug("cr3\t0x%016llx\n", sregs.cr3);
}

#else

#define dump_regs(...)

#endif /* DEBUG */

#endif /* DEBUG_H */
