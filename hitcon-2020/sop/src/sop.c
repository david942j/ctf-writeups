#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void *read_file(char *filename) {
  int fd = open(filename, O_RDONLY);
  assert(fd >= 0);
  struct stat sb;
  assert(fstat(fd, &sb) != -1);
  void *code = mmap(0, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  assert(code != MAP_FAILED);
  close(fd);
  return code;
}

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

static inline u32 getbit(u64 *val, int b) {
  u32 ret = (*val) & ((1ul << b) - 1);
  (*val) >>= b;
  return ret;
}

/*
 * 8-bit nr
 * 2-bit
 *  - 0: follows 4 bits value v, indicating use regs[v]
 *  - 1: follows 4 bits value v, indicating use &regs[v]
 *  - 2: follows 5 bits value v, indicating use the following 2 ** (v-1) bits | 2 ** v immi
 *  - 3: end of arguments
 *
 * mmap(regs[0], 1, 7, 0x22, 0, 0)
 * 8 + (2 + 4) + (2 + 5 + 1) + (2 + 5 + 3) + (2 + 5 + 6) + (2 + 5 + 1) + (2 + 5 + 1) + 2
 * = 8 + 6 + 8 * 5 + 9 = 63
 */
static void fetch_inst(u64 val, u64 *nr, u64 args[], const u64 regs[]) {
  *nr = getbit(&val, 8);

  for (int i = 0; i < 6; i++) {
    u8 t = getbit(&val, 2);
    if (t == 0)
      args[i] = regs[getbit(&val, 4)];
    else if (t == 1)
      args[i] = (u64) &regs[getbit(&val, 4)];
    else if (t == 2) {
      u8 b = getbit(&val, 5);
      args[i] = getbit(&val, b + 1);
    }
    else break;
  }
}

#define rip regs[15]
static void run(u64 *code) {
  u64 regs[16] = {};
  while (code[rip]) {
    u64 nr, args[6];
    fetch_inst(code[rip], &nr, args, regs);
    syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]);
    rip++;
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <sop_bytecode_file>\n", argv[0]);
    return 2;
  }
  run(read_file(argv[1]));
  return 0;
}
