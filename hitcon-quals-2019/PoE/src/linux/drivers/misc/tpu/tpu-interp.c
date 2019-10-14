/*
 * Provides high-level API to communicate with TPU.
 *
 * Copyright (c) 2019 david942j
 */

#include <linux/errno.h>
#include <linux/param.h>
#include <linux/slab.h>

#include "tpu-internal.h"
#include "tpu-spec.h"

#define PANIC_ON(condition) do { if (unlikely((condition)!=0)) { \
    printk("failure at %s:%d/%s()!\n", __FILE__, __LINE__, __FUNCTION__); \
    panic("BUG"); \
  } \
} while(0)

static void emit(struct tpu_device *tdev, u64 code)
{
	PANIC_ON(tdev->inst_cnt >= ARRAY_SIZE(tdev->inst));

	tdev->inst[tdev->inst_cnt++] = code;
}

#define SS(r, i) ((u64)(r) << i)

static void command_version(struct tpu_device *tdev)
{
	emit(tdev, TPU_OP_VERSION);
}

static void command_new(struct tpu_device *tdev, enum TPU_REG r, u8 w, uint n)
{
	emit(tdev, TPU_OP_NEW | SS(r, 4) | SS(w, 8) | SS(n, 12));
}

/* @r holds Node *, query its tid */
static void command_info(struct tpu_device *tdev, enum TPU_REG r)
{
	emit(tdev, TPU_OP_INFO | SS(r, 4));
}

static void command_load(struct tpu_device *tdev, enum TPU_REG r, uint tid)
{
	emit(tdev, TPU_OP_LOAD | SS(r, 4) | SS(tid, 8));
}

static void command_split(struct tpu_device *tdev, enum TPU_REG s, uint x, enum TPU_REG d1, enum TPU_REG d2)
{
	emit(tdev, TPU_OP_SPLIT | SS(s, 4) | SS(x, 8) | SS(d1, 40) | SS(d2, 44));
}

static void command_merge(struct tpu_device *tdev, enum TPU_REG d, enum TPU_REG s1, enum TPU_REG s2)
{
	emit(tdev, TPU_OP_MERGE | SS(d, 4) | SS(s1, 8) | SS(s2, 12));
}

static void command_print(struct tpu_device *tdev, enum TPU_REG r)
{
	emit(tdev, TPU_OP_PRINT | SS(r, 4));
}

static void command_delete(struct tpu_device *tdev, enum TPU_REG r)
{
	emit(tdev, TPU_OP_DELETE | SS(r, 4));
}

static void command_reverse(struct tpu_device *tdev, enum TPU_REG r)
{
	emit(tdev, TPU_OP_REVERSE | SS(r, 4));
}

static void command_cover(struct tpu_device *tdev, enum TPU_REG r, u64 val)
{
	emit(tdev, TPU_OP_COVER | SS(r, 4));
	emit(tdev, val);
}

static inline bool queue_full(u64 head, u64 tail)
{
	return (head ^ tail) == QUEUE_WRAP_BIT;
}

static int push_cmd(struct tpu_device *tdev, struct cmd_element *cmd)
{
	u64 head = tdev->csrs[TPU_CSR_CMD_HEAD];
	u64 tail = tdev->cmd_tail;
	u32 total = sizeof(*cmd) + cmd->count * sizeof(u64);
	unsigned char *c = (unsigned char *)cmd;
	u32 i;

	for (i = 0; i < total; i++) {
		if (queue_full(head, tail)) /* should never happen */
			return -EBUSY;
		tdev->cmd_queue[QUEUE_REAL_INDEX(tail)] = c[i];
		tail = (tail + 1) & QUEUE_INDEX_MASK;
	}
	tdev->csrs[TPU_CSR_CMD_TAIL] = tdev->cmd_tail = tail;
	return 0;
}

#define prepare(tdev) \
  do { \
	mutex_lock(&tdev->command_lock); \
	tdev->inst_cnt = 0; \
  } while (0)

#define commit0(tdev) \
  do { \
	int ret = _commit(tdev, 0, NULL); \
	mutex_unlock(&tdev->command_lock); \
	if (ret) \
		return ret; \
	return 0; \
  } while (0)

#define commit1(tdev, handlers) \
  do { \
	int ret = _commit(tdev, 1, handlers); \
	mutex_unlock(&tdev->command_lock); \
	if (ret) { \
		kfree(handlers); \
		return ret; \
	} \
	ret = handlers[0].retval; \
	kfree(handlers); \
	return ret; \
  } while (0)

#define commit(tdev, n, handlers) \
  do { \
	int ret = _commit(tdev, n, handlers); \
	mutex_unlock(&tdev->command_lock); \
	if (ret) { \
		kfree(handlers); \
		return ret; \
	} \
  } while (0)

/* returns 0 on success, or -ETIME if reaches a timeout */
static int _commit(struct tpu_device *tdev, u8 n, struct tpu_rsp_handler *handlers)
{
	struct cmd_element *cmd = kzalloc(sizeof(*cmd) + tdev->inst_cnt * sizeof(u64), GFP_KERNEL);
	int ret;

	if (!cmd)
		return -ENOMEM;

	cmd->count = tdev->inst_cnt;
	memcpy(cmd->inst, tdev->inst, tdev->inst_cnt * sizeof(u64));
	ret = push_cmd(tdev, cmd);
	kfree(cmd);
	if (ret)
		return ret;
	debug("%s: %u instructions\n", __func__, tdev->inst_cnt);
	debug("%s: cmd_head: %llu, cmd_tail: %llu\n", __func__, tdev->csrs[TPU_CSR_CMD_HEAD], tdev->cmd_tail);
	spin_lock(&tdev->irq_lock);
	PANIC_ON(tdev->rsp_handlers);
	tdev->rsp_handlers = handlers;
	tdev->num_handlers = n;
	tdev->irq_handled = 0;
	spin_unlock(&tdev->irq_lock);
	tdev->csrs[TPU_CSR_CMD_SENT] = 1;
	if (!wait_event_timeout(tdev->waitq, tdev->irq_handled, HZ)) {
		/* give up */
		spin_lock(&tdev->irq_lock);
		tdev->rsp_handlers = NULL;
		tdev->num_handlers = 0;
		spin_unlock(&tdev->irq_lock);
		return -ETIME;
	}

	return 0;
}

static bool fetch_rsp(struct tpu_device *tdev, int n, u8 *c)
{
	u64 head = tdev->rsp_head, tail = tdev->csrs[TPU_CSR_RSP_TAIL];
	int i;

	debug("%s: rsp_head: %llu, rsp_tail: %llu\n", __func__, head, tail);
	for (i = 0; i < n; i++) {
		if (head == tail) {
			tdev->rsp_head = head;
			tdev->csrs[TPU_CSR_RSP_HEAD] = head;
			return false;
		}
		c[i] = tdev->rsp_queue[QUEUE_REAL_INDEX(head)];
		head = (head + 1) & QUEUE_INDEX_MASK;
	}

	tdev->rsp_head = head;
	tdev->csrs[TPU_CSR_RSP_HEAD] = head;

	return true;
}

#define DECLARE_HANDLER1(handler, _data) \
  struct tpu_rsp_handler *handler = kzalloc(sizeof(*handler), GFP_KERNEL); \
  if (!handler) return -ENOMEM; \
  handler->data = _data;

static int tpu_hw_version_handle(struct tpu_device *tdev)
{
	int ret = 0;

	if (!fetch_rsp(tdev, 2, (u8 *)&ret))
		return -EBADMSG;
	return ret;
}

/* fetch tid */
static int tpu_info_handle(struct tpu_device *tdev)
{
	int ret;

	if (!fetch_rsp(tdev, 4, (u8 *)&ret))
		return -EBADMSG;
	return ret;
}

struct tpu_print_args {
	u8 width;
	u8 *data;
};

static int tpu_print_handle(struct tpu_device *tdev, void *arg_)
{
	struct tpu_print_args *arg = arg_;
	uint sz = 0;

	if (!fetch_rsp(tdev, 1, (u8 *)&sz))
		return -EBADMSG;
	if (!fetch_rsp(tdev, sz * arg->width, arg->data))
		return -EBADMSG;
	return 0;
}

/* fetch op and call the handler */
int tpu_rsp_handle(struct tpu_device *tdev, void *arg)
{
	enum TPU_OP op = TPU_OP_END;

	if (!fetch_rsp(tdev, 1, (u8 *)&op))
		return -EBADMSG;
	switch (op) {
	case TPU_OP_VERSION:
		return tpu_hw_version_handle(tdev);
	case TPU_OP_PRINT:
		return tpu_print_handle(tdev, arg);
	case TPU_OP_INFO:
		return tpu_info_handle(tdev);
	default:
		return -EBADMSG;
	};
}

int tpu_hw_version(struct tpu_device *tdev)
{
	DECLARE_HANDLER1(handler, NULL);

	prepare(tdev);
	command_version(tdev);
	commit1(tdev, handler);
}

/* returns tid */
int tpu_new_tree(struct tpu_device *tdev, uint n, u8 w, void *data)
{
	DECLARE_HANDLER1(handler, NULL);

	memcpy(tdev->data, data, n * w);

	prepare(tdev);
	command_new(tdev, TPU_R0, w, n);
	command_info(tdev, TPU_R0);
	commit1(tdev, handler);
}

/* return 0 or errno */
int tpu_display(struct tpu_device *tdev, int tid, uint cur, uint len, u8 w, void *data)
{
	const int n = 3;
	int i;
	struct tpu_print_args arg = {
		.width = w,
		.data = data,
	};
	struct tpu_rsp_handler *handlers = kcalloc(n, sizeof(*handlers), GFP_KERNEL);
	/* printk("%s: size=%u handlers @\t%#llx\n", __func__, n * sizeof(*handlers), (u64)handlers); */

	if (!handlers)
		return -ENOMEM;
	handlers[1].data = &arg;

	prepare(tdev);

	command_load(tdev, TPU_R0, tid);
	command_split(tdev, TPU_R0, cur, TPU_R0, TPU_R1);
	command_split(tdev, TPU_R1, len, TPU_R1, TPU_R2);
	command_info(tdev, TPU_R1);
	command_print(tdev, TPU_R1);
	command_merge(tdev, TPU_R1, TPU_R1, TPU_R2);
	command_merge(tdev, TPU_R0, TPU_R0, TPU_R1);

	/* to check tid is not changed */
	command_info(tdev, TPU_R0);

	commit(tdev, n, handlers);

	for (i = 0; i < n; i++) {
		int ret = handlers[i].retval;

		if (ret < 0) {
			kfree(handlers);
			return ret;
		}
	}
	if (tid != handlers[2].retval) {
		debug("%s: expected tid=%d, got tid=%d\n", __func__, tid, handlers[2].retval);
		kfree(handlers);
		return -EBADMSG;
	}
	kfree(handlers);
	return 0;
}

int tpu_cut(struct tpu_device *tdev, int tid, uint cur, uint len, int *out_tid1, int *out_tid2)
{
	int i;
	const int n = 2;
	struct tpu_rsp_handler *handlers = kcalloc(n, sizeof(*handlers), GFP_KERNEL);

	if (!handlers)
		return -ENOMEM;

	prepare(tdev);

	command_load(tdev, TPU_R0, tid);
	command_split(tdev, TPU_R0, cur, TPU_R0, TPU_R1);
	command_split(tdev, TPU_R1, len, TPU_R1, TPU_R2);
	command_merge(tdev, TPU_R0, TPU_R0, TPU_R2);
	command_info(tdev, TPU_R0);
	command_info(tdev, TPU_R1);

	commit(tdev, n, handlers);

	for (i = 0; i < n; i++) {
		int ret = handlers[i].retval;

		if (ret < 0) {
			kfree(handlers);
			return ret;
		}
	}
	*out_tid1 = handlers[0].retval;
	*out_tid2 = handlers[1].retval;
	kfree(handlers);
	return 0;
}

/* returns new tid */
int tpu_paste(struct tpu_device *tdev, int tid1, uint cur, int tid2)
{
	DECLARE_HANDLER1(handler, NULL);

	prepare(tdev);

	command_load(tdev, TPU_R0, tid1);
	command_split(tdev, TPU_R0, cur, TPU_R0, TPU_R2);
	command_load(tdev, TPU_R1, tid2);
	command_merge(tdev, TPU_R0, TPU_R0, TPU_R1);
	command_merge(tdev, TPU_R0, TPU_R0, TPU_R2);
	command_info(tdev, TPU_R0);

	commit1(tdev, handler);
}

/* always returns 0 */
int tpu_delete(struct tpu_device *tdev, int tid)
{
	prepare(tdev);

	command_load(tdev, TPU_R0, tid);
	command_delete(tdev, TPU_R0);

	commit0(tdev);
}


/* always returns 0 */
int tpu_reverse(struct tpu_device *tdev, int tid, uint cur, uint len)
{
	prepare(tdev);

	command_load(tdev, TPU_R0, tid);
	command_split(tdev, TPU_R0, cur, TPU_R0, TPU_R1);
	command_split(tdev, TPU_R1, len, TPU_R1, TPU_R2);
	command_reverse(tdev, TPU_R1);
	command_merge(tdev, TPU_R1, TPU_R1, TPU_R2);
	command_merge(tdev, TPU_R0, TPU_R0, TPU_R1);

	commit0(tdev);
}

/* always returns 0 */
int tpu_cover(struct tpu_device *tdev, int tid, uint cur, uint len, u64 val)
{
	prepare(tdev);

	command_load(tdev, TPU_R0, tid);
	command_split(tdev, TPU_R0, cur, TPU_R0, TPU_R1);
	command_split(tdev, TPU_R1, len, TPU_R1, TPU_R2);
	command_cover(tdev, TPU_R1, val);
	command_merge(tdev, TPU_R1, TPU_R1, TPU_R2);
	command_merge(tdev, TPU_R0, TPU_R0, TPU_R1);

	commit0(tdev);
}
