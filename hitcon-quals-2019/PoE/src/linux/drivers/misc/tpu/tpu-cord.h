/*
 * Cord - the next generation string implementation.
 *
 * Copyright (c) 2019 david942j
 */
#ifndef _TPU_CORD_H
#define _TPU_CORD_H

#include <linux/fs.h>

struct tpu_device;

#define MAX_CID 255
struct tpu_cord {
	struct tpu_device *tdev;
	u8 data_width; /* can only be 1, 2, 4, 8; default: 1 */
	u64 cid_map[MAX_CID + 1];
};

extern const struct file_operations tpu_cord_ops;

#endif /* _TPU_CORD_H */
