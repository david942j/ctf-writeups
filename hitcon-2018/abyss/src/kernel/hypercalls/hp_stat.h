#ifndef HP_STAT_H
#define HP_STAT_H

#include <stdint.h>

#include <hypercalls/hypercall.h>

int hp_fstat(int fildes, uint64_t phy_addr);

#endif
