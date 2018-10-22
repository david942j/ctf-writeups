#ifndef MISC_H
#define MISC_H

#include <stdint.h>

#define aligndown(v) ((uint64_t) (v) & -0x1000)
#define alignup(v) (((uint64_t) (v) & 0xfff) ? aligndown(v) + 0x1000 : (uint64_t) (v))
#define alignok(v) ((uint64_t) (v) == aligndown(v))

#define MAX(a,b) ((a) > (b) ? (a) : (b))

#define offsetof(TYPE, MEMBER) ((uint64_t) &((TYPE *)0)->MEMBER)

uint64_t random();

#endif

