#ifndef HP_ACCESS_H
#define HP_ACCESS_H

#include <stdint.h>

#include <hypercalls/hypercall.h>

int hp_access(uint32_t paddr, int mode);

#endif
