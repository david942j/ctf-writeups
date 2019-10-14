/*
 * Internal common interface for TPU driver.
 *
 * Copyright (c) 2019 david942j
 */
#ifndef _TPU_INTERNAL_H
#define _TPU_INTERNAL_H

// #define DAVID942J

#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#ifdef DAVID942J
 #define debug(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
 #define debug(...)
#endif /* DAVID942j */

struct tpu_rsp_handler;

struct tpu_device {
	/* PCI related fields */
	struct device *dev;
	phys_addr_t csrs_phys, cmd_queue_phys, rsp_queue_phys, data_phys;
	u64 *csrs;
	u8 *cmd_queue, *rsp_queue;
	void *data;

	struct miscdevice corddev;
	struct mutex command_lock;
	wait_queue_head_t waitq; /* wait for device responses */

	spinlock_t irq_lock; /* protects rsp_handlers, num_handlers, irq_handled */
	struct tpu_rsp_handler *rsp_handlers;
	u8 num_handlers;
	u8 irq_handled;

	u64 cmd_tail, rsp_head;
	u8 inst_cnt;
	u64 inst[128];
};

struct tpu_rsp_handler {
	void *data;
	int retval;
};

int tpu_init(struct tpu_device *tdev);
void tpu_exit(struct tpu_device *tdev);
void tpu_reset(struct tpu_device *tdev);

/* APIs to communicate with TPU device, implemented in tpu-interp.c */

int tpu_rsp_handle(struct tpu_device *tdev, void *data);
int tpu_hw_version(struct tpu_device *tdev);
int tpu_new_tree(struct tpu_device *tdev, uint n, u8 w, void *data);
int tpu_display(struct tpu_device *tdev, int tid, uint cur, uint len, u8 w, void *data);
int tpu_cut(struct tpu_device *tdev, int tid, uint cur, uint len, int *out_tid1, int *out_tid2);
int tpu_paste(struct tpu_device *tdev, int tid1, uint cur, int tid2);
int tpu_delete(struct tpu_device *tdev, int tid);
int tpu_reverse(struct tpu_device *tdev, int tid, uint cur, uint len);
int tpu_cover(struct tpu_device *tdev, int tid, uint cur, uint len, u64 val);

#endif /* _TPU_INTERNAL_H */
