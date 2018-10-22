#include <utils/misc.h>

uint64_t random() {
  register uint64_t low asm("rax");
  register uint64_t hi asm("rdx");
  asm("rdtsc");
  low = low * 0x391377 + 0x33da21;
  hi = hi * 0x9aac8d13 + 0x38a1bbc;
  return (low << 32) | hi;
}
