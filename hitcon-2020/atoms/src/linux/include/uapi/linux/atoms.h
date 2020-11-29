/*
 * ATOMS interfaces shared with user-space.
 *
 * Copyright (c) 2020 david942j
 */
#ifndef _UAPI_LINUX_ATOMS_H
#define _UAPI_LINUX_ATOMS_H

#include <linux/ioctl.h>

#define ATOMSIO 217

#define ATOMS_USE_TOKEN _IOW(ATOMSIO, 0, unsigned long long)

struct atoms_ioctl_info {
  unsigned long long token;
  size_t num_pages;
  size_t num_segments;
};

#define ATOMS_INFO _IOR(ATOMSIO, 1, struct atoms_ioctl_info)

struct atoms_ioctl_alloc {
  size_t size; /* in */
  size_t offset; /* out */
};

#define ATOMS_ALLOC _IOWR(ATOMSIO, 2, struct atoms_ioctl_alloc)

#define ATOMS_RELEASE _IO(ATOMSIO, 3)

#endif /* _UAPI_LINUX_ATOMS_H */
