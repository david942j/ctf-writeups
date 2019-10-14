/*
 * Cord driver runtime interface.
 *
 * Copyright (c) 2019 david942j
 */
#ifndef _UAPI_LINUX_CORD_H
#define _UAPI_LINUX_CORD_H

#include <linux/ioctl.h>

#define CORDIO 217

#define CORD_GET_DEVICE_VERSION _IO(CORDIO, 0)
#define CORD_SET_DATA_WIDTH _IOR(CORDIO, 1, unsigned int)

struct cord_new_data {
	unsigned int n;
	void *data; /* @data should have @n * data_width bytes */
};

#define CORD_NEW_DATA _IOR(CORDIO, 2, struct cord_new_data)

struct cord_display {
	unsigned int cid;
	unsigned int cur, len;
	void *data; /* @data should have @len * data_width bytes */
};

struct cord_cut {
	unsigned int cid;
	unsigned int cur, len;
};

struct cord_paste {
	unsigned int cid_d;
	unsigned int cur;
	unsigned int cid_s;
};

struct cord_reverse {
	unsigned int cid;
	unsigned int cur, len;
};

struct cord_cover {
	unsigned int cid;
	unsigned int cur, len;
	unsigned long long val;
};

#define CORD_DISPLAY _IOR(CORDIO, 3, struct cord_display)
#define CORD_CUT _IOR(CORDIO, 4, struct cord_cut)
#define CORD_PASTE _IOR(CORDIO, 5, struct cord_paste)
#define CORD_DELETE _IOR(CORDIO, 6, unsigned int)
#define CORD_REVERSE _IOR(CORDIO, 7, struct cord_reverse)
#define CORD_COVER _IOR(CORDIO, 8, struct cord_cover)

#endif /* _UAPI_LINUX_CORD_H */
