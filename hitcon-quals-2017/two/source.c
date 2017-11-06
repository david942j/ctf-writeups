#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

char t[] = "H\xb8H\xb9H\xbaH\xbbH\xbcH\xbdH\xbeH\xbfI\xb8I\xb9I\xbaI\xbbI\xbcI\xbdI\xbeI\xbf";
int rd;
inline void* random_mmap(int perm) {
  size_t r;
  void *addr;
  read(rd, &r, 6);
  addr = (void*) (r & 0x7ffffffff000ll);
  addr = mmap(addr, 4096, perm, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if(addr == MAP_FAILED) exit(1);
  return addr;
}
int main() {
  char c[16];
  memset(c, 0xee, 16);
  alarm(30);
  rd = open("/dev/urandom", O_RDONLY);
  printf("%#llx\n", __builtin_return_address(0));
  fflush(stdout);
  register void* addr = random_mmap(PROT_WRITE | PROT_EXEC);
  void *stk = random_mmap(PROT_WRITE | PROT_READ);
  memset(stk, 0xee, 0x1000);
  char *p = (char*)addr;
  for(int i=0,j=0;i<16;i++) {
    *p = t[j++]; p++;
    *p = t[j++]; p++;
    if(i == 4)
      *(size_t *)p = stk + 2048;
    else
      read(rd, p, 8);
    p += 8;
  }
  close(rd);
  *p = (unsigned char)0xc3;
  read(0, c, 16);
  memcpy(stk + 2048, c, 16);
  __asm__("jmp *%0" : : "r" (addr));
  _exit(0);
}
