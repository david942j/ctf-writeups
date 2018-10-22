#include <elf/elf.h>
#include <hypercalls/hp_read.h>
#include <mm/kmalloc.h>
#include <mm/mmap.h>
#include <mm/translate.h>
#include <mm/uaccess.h>
#include <syscalls/sys_close.h>
#include <syscalls/sys_execve.h>
#include <syscalls/sys_mmap.h>
#include <syscalls/sys_open.h>
#include <syscalls/sys_read.h>
#include <utils/errno.h>
#include <utils/misc.h>
#include <utils/string.h>

static int load_binary(int fd, process* p) {
  void *buf = kmalloc(0x1000, MALLOC_NO_ALIGN);
  hp_read(fd, physical(buf), 0x1000);
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*) buf;
  if(memcmp(ehdr->e_ident, "\177ELF\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16) != 0)
    return -ENOEXEC;
  p->entry = ehdr->e_entry;
  p->load_addr = 0;
  if(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) return -ENOEXEC;
  if(ehdr->e_type == ET_DYN) p->load_addr = 0x0000555555554000ull + (random() % 0x1f987651u) * 0x1000;
  if(ehdr->e_phoff != sizeof(*ehdr)) return -EINVAL;
  if(ehdr->e_phentsize != sizeof(Elf64_Phdr)) return -EINVAL;
  if(ehdr->e_phoff + (uint64_t) ehdr->e_phentsize * ehdr->e_phnum > 0x1000)
    return -EINVAL;
  Elf64_Phdr *phdr = (Elf64_Phdr*) ((uint8_t*) buf + ehdr->e_phoff);
  brk_end = 0;
  p->phnum = ehdr->e_phnum;
  for(int i = 0; i < ehdr->e_phnum; i++, phdr++)
    if(phdr->p_type == PT_LOAD) {
      uint64_t sz = phdr->p_filesz;
      uint64_t st = p->load_addr + aligndown(phdr->p_vaddr),
               ed = p->load_addr + alignup(phdr->p_vaddr + sz);
      int prot = pf_to_prot(phdr->p_flags);
      /* not a good idea, but it works */
      void *r = sys_mmap(
        (void*) st, sz + (phdr->p_offset & 0xfff), prot,
        MAP_FIXED, fd, phdr->p_offset & -0x1000
      );
      if(r != (void*) st) return (int) (int64_t) r; // error returned by sys_mmap

      brk_end = MAX(brk_end, ed);
      if(phdr->p_memsz > sz) {
        uint64_t bss_ed = p->load_addr + alignup(phdr->p_vaddr + phdr->p_memsz);
        if(bss_ed != ed) {
          if(mmap((void*) ed, bss_ed - ed, prot) != (void*) ed)
            return -ENOMEM;
        }
        brk_end = MAX(brk_end, bss_ed);
      }
    }
  /* set up stack */
  p->stack_base = 0x00007ffffffff000ull - (random() % 0x7331) * 0x1000;
  p->stack_size = 0x40000;
  p->rsp = p->stack_base - 0x1000 - (random() % 0xff * 0x10);
  void *st = (void*) (p->stack_base - p->stack_size);
  if(mmap(st, p->stack_size, PROT_RW) != st) return -ENOMEM;
  return 0;
}

static int check_and_get_count(char *const ary[]) {
  if(!access_ok(VERIFY_READ, ary, 8)) return -EFAULT;
  int i = 0;
  while(*ary != 0) {
    if(!access_string_ok(*ary)) return -EFAULT;
    ++ary;
    ++i;
    if(!access_ok(VERIFY_READ, ary, 8)) return -EFAULT;
  }
  return i;
}

#define STACK_ALLOC(sp, len) ({ sp -= len ; (uint64_t*) sp; })
#define ROUNDDOWN(sp) sp &= -0x10

static int create_elf_info(process *p, char *const argv[], char *const envp[]) {
  /* we must push strings first */
  char *exec_fn = (char*) STACK_ALLOC(p->rsp, strlen(p->filename) + 1);
  memcpy(exec_fn, p->filename, strlen(p->filename) + 1);

  char *u_platform = (char*) STACK_ALLOC(p->rsp, strlen(ELF_PLATFORM) + 1);
  memcpy(u_platform, ELF_PLATFORM, strlen(ELF_PLATFORM) + 1);

  /* push argv and envp onto stack */
  int argc = check_and_get_count(argv);
  if(argc < 0) return argc;
  int envc = check_and_get_count(envp);
  if(envc < 0) return envc;

  char **copy = (char**) kmalloc((argc + envc + 2) * sizeof(char*), MALLOC_NO_ALIGN);
  for(int i = envc - 1; i >= 0; i--) {
    uint64_t len = strlen(envp[i]) + 1;
    copy[argc + 1 + i] = (char*) STACK_ALLOC(p->rsp, len);
    memcpy(copy[argc + 1 + i], envp[i], len);
  }

  for(int i = argc - 1; i >= 0; i--) {
    uint64_t len = strlen(argv[i]) + 1;
    copy[i] = (char*) STACK_ALLOC(p->rsp, len);
    memcpy(copy[i], argv[i], len);
  }

  uint64_t *u_rand_bytes = STACK_ALLOC(p->rsp, 16);
  u_rand_bytes[0] = 0xdeadbeefcafebabeull;
  u_rand_bytes[1] = 0x12345678abcdef90ull;

  uint64_t *elf_info = kmalloc(MAX_AUXV_NUM * 2 * sizeof(uint64_t),
    MALLOC_NO_ALIGN);
  int ei_index = 0;
#define NEW_AUX_ENT(id, val) \
	do { \
		elf_info[ei_index++] = id; \
		elf_info[ei_index++] = (uint64_t) val; \
	} while (0)
  NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
  NEW_AUX_ENT(AT_PAGESZ, 0x1000);
  NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
  NEW_AUX_ENT(AT_PHDR, p->load_addr + sizeof(Elf64_Ehdr));
  NEW_AUX_ENT(AT_PHENT, sizeof(Elf64_Phdr));
  NEW_AUX_ENT(AT_PHNUM, p->phnum);
  NEW_AUX_ENT(AT_BASE, 0);
  NEW_AUX_ENT(AT_FLAGS, 0);
  NEW_AUX_ENT(AT_ENTRY, p->load_addr + p->entry);
  NEW_AUX_ENT(AT_UID, 0);
  NEW_AUX_ENT(AT_EUID, 0);
  NEW_AUX_ENT(AT_GID, 0);
  NEW_AUX_ENT(AT_EGID, 0);
  NEW_AUX_ENT(AT_SECURE, 0);
  NEW_AUX_ENT(AT_RANDOM, u_rand_bytes);
  NEW_AUX_ENT(AT_HWCAP2, 0);
  NEW_AUX_ENT(AT_EXECFN, exec_fn);
  NEW_AUX_ENT(AT_PLATFORM, u_platform);
  NEW_AUX_ENT(AT_NULL, 0);
#undef NEW_AUX_ENT

  /* program is happier if rsp is aligned */
  /* The final rsp must be 16-byte aligned, so we calculate how many bytes
   * will be copied later, and round the rsp here.
   */
  ROUNDDOWN(p->rsp);
  /* auxv always contains 16x bytes, so we can ignore it */
  if((argc + 1 + envc + 1 + 1) & 1) STACK_ALLOC(p->rsp, 8);

  /* push auxv */
  STACK_ALLOC(p->rsp, ei_index * sizeof(uint64_t));
  memcpy((void*) p->rsp, elf_info, ei_index * sizeof(uint64_t));
  kfree(elf_info);

  /* push envp and argv onto stack */
  for(int i = argc + envc + 1; i >= 0; i--)
    *(char**) STACK_ALLOC(p->rsp, 8) = copy[i];
  kfree(copy);

  /* last step, push argc onto it */
  *(uint64_t*) STACK_ALLOC(p->rsp, 8) = argc;
  return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
  int fd = sys_open(path);
  if(fd < 0) return fd;
  process p = {};
  int ret = load_binary(fd, &p);
  if(ret < 0) return ret;
  sys_close(fd);
  p.filename = copy_str_from_user(path);
  if(create_elf_info(&p, argv, envp)) return -EFAULT;
  /* this is an execve call so we can ignore the saved registers (rip, rsp) */
  asm volatile(
    "mov [rip + kernel_stack], rsp;"
    "mov rcx, %[entry];" /* rip */
    "mov r11, 0x2;"      /* rflags */
    "mov rsp, %[rsp];"
    /* clean up registers */
    "xor rax, rax;"
    "xor rbx, rbx;"
    "xor rdx, rdx;"
    "xor rdi, rdi;"
    "xor rsi, rsi;"
    "xor rbp, rbp;"
    "xor r8, r8;"
    "xor r9, r9;"
    "xor r10, r10;"
    "xor r12, r12;"
    "xor r13, r13;"
    "xor r14, r14;"
    "xor r15, r15;"
    "xor rbp, rbp;"
    ".byte 0x48;"
    "sysret"
    :: [entry]"r"(p.entry + p.load_addr), [rsp]"r"(p.rsp)
    : "r11", "rcx"
  );
  /* never reached */
  return -EPERM;
}
