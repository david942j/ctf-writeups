/*
 * SPARK interfaces shared with user-space.
 *
 * Copyright (c) 2020 david942j
 */
#ifndef _UAPI_LINUX_SPARK_H
#define _UAPI_LINUX_SPARK_H

#include <linux/ioctl.h>

#define SPARKIO 217

#define SPARK_LINK _IOW(SPARKIO, 0, unsigned long long)

struct spark_ioctl_info {
  size_t nnb; /* number of neighbors */
  size_t idx;
  size_t graph_size;
};

#define SPARK_INFO _IOR(SPARKIO, 1, struct spark_ioctl_info)

#define SPARK_FINALIZE _IO(SPARKIO, 2)

struct spark_ioctl_query {
  int fd1;
  int fd2;
  long long distance;
};

#define SPARK_QUERY _IOWR(SPARKIO, 3, struct spark_ioctl_query)

#endif /* _UAPI_LINUX_SPARK_H */
