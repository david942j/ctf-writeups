#ifndef SYS_EXECVE_H
#define SYS_EXECVE_H

#include <stdint.h>

#define ELF_PLATFORM "x86_64"
#define ELF_HWCAP 0xbfebfbff
#define CLOCKS_PER_SEC 100
typedef struct process {
  char *filename;
  uint64_t load_addr;
  uint32_t phnum;
  uint64_t entry;
  uint64_t stack_base;
  uint64_t stack_size;
  uint64_t rsp;
} process;

int sys_execve(const char *path, char *const argv[], char *const envp[]);

#endif
