/*
 * Cord - the next generation string implementation.
 *
 * Copyright (c) 2019 david942j
 */

#include <linux/cord.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "tpu-cord.h"
#include "tpu-internal.h"

#define MAX_CMD_N 255

static struct mutex open_lock;
static bool opening;

static int tpu_cord_avail_cid(struct tpu_cord *cord)
{
	int i;

	for (i = 0; i <= MAX_CID; i++)
		if (cord->cid_map[i] == 0)
			return i;
	return -1;
}

static bool tpu_cord_find_cid(struct tpu_cord *cord, u32 cid, u32 *tid, u32 *len)
{
	u64 val;

	if (cid > MAX_CID)
		return false;
	val = cord->cid_map[cid];

	if ((val >> 32) == 0)
		return false;
	if (tid)
		*tid = val & 0xffffffff;
	if (len)
		*len = val >> 32;
	return true;
}

static void tpu_cord_set_map(struct tpu_cord *cord, uint cid, uint tid, uint len)
{
	cord->cid_map[cid] = ((u64)len << 32) | tid;
}

#define CONDITION_CUR_LEN_SZ(c, s) \
	(c.len == 0 || c.cur >= s || c.len > s || c.cur > s - c.len)

static int tpu_cord_cut(struct tpu_cord *cord, struct cord_cut __user *argp)
{
	struct cord_cut cmd;
	int tid, tid2, ret, ncid;
	u32 sz;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;
	if (!tpu_cord_find_cid(cord, cmd.cid, &tid, &sz))
		return -EINVAL;
	if (CONDITION_CUR_LEN_SZ(cmd, sz) || (cmd.cur == 0 && sz == cmd.len))
		return -EINVAL;

	ncid = tpu_cord_avail_cid(cord);
	if (ncid < 0)
		return -EMFILE;

	ret = tpu_cut(cord->tdev, tid, cmd.cur, cmd.len, &tid, &tid2);
	if (WARN_ON(ret < 0)) // should never happen
		goto out;
	tpu_cord_set_map(cord, cmd.cid, tid, sz - cmd.len);
	tpu_cord_set_map(cord, ncid, tid2, cmd.len);
	return ncid;
out:
	tpu_cord_set_map(cord, cmd.cid, 0, 0);
	return ret;
}

static int tpu_cord_reverse(struct tpu_cord *cord, struct cord_reverse __user *argp)
{
	struct cord_reverse cmd;
	int tid;
	u32 sz;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;
	if (!tpu_cord_find_cid(cord, cmd.cid, &tid, &sz))
		return -EINVAL;
	if (CONDITION_CUR_LEN_SZ(cmd, sz))
		return -EINVAL;

	return WARN_ON(tpu_reverse(cord->tdev, tid, cmd.cur, cmd.len));
}

static int tpu_cord_cover(struct tpu_cord *cord, struct cord_cover __user *argp)
{
	struct cord_cover cmd;
	int tid;
	u32 sz;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;
	if (!tpu_cord_find_cid(cord, cmd.cid, &tid, &sz))
		return -EINVAL;
	if (CONDITION_CUR_LEN_SZ(cmd, sz))
		return -EINVAL;

	return WARN_ON(tpu_cover(cord->tdev, tid, cmd.cur, cmd.len, cmd.val));
}

static int tpu_cord_paste(struct tpu_cord *cord, struct cord_paste __user *argp)
{
	struct cord_paste cmd;
	int tid1, tid2, ret;
	u32 sz1, sz2;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;
	if (!tpu_cord_find_cid(cord, cmd.cid_d, &tid1, &sz1))
		return -EINVAL;
	if (!tpu_cord_find_cid(cord, cmd.cid_s, &tid2, &sz2))
		return -EINVAL;
	if (cmd.cid_d == cmd.cid_s || tid1 == tid2)
		return -EINVAL;
	if (cmd.cur > sz1)
		return -EINVAL;
	tpu_cord_set_map(cord, cmd.cid_s, 0, 0);
	ret = tpu_paste(cord->tdev, tid1, cmd.cur, tid2);
	if (ret < 0) // if width not matched
		goto out;
	tpu_cord_set_map(cord, cmd.cid_d, ret, sz1 + sz2);
	return 0;
out:
	tpu_cord_set_map(cord, cmd.cid_d, 0, 0);
	return ret;
}

static int tpu_cord_display(struct tpu_cord *cord, struct cord_display __user *argp)
{
	struct cord_display cmd;
	u32 sz;
	int tid;
	int ret = 0;
	void *data;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;
	if (!tpu_cord_find_cid(cord, cmd.cid, &tid, &sz))
		return -EINVAL;
	if (CONDITION_CUR_LEN_SZ(cmd, sz) || cmd.len > MAX_CMD_N)
		return -EINVAL;
	/* if (!access_ok(cmd.data, cmd.len * cord->data_width)) */
	/*         return -EFAULT; */
	data = kcalloc(cmd.len, cord->data_width, GFP_KERNEL);
	/* printk("%s: size=%u data @ %#llx\n", __func__, cmd.len * cord->data_width, data); */
	if (!data)
		return -ENOMEM;
	ret = tpu_display(cord->tdev, tid, cmd.cur, cmd.len, cord->data_width, data);
	if (ret < 0)
		goto out;
	if (copy_to_user(cmd.data, data, cord->data_width * cmd.len)) {
		ret = -EFAULT;
		goto out;
	}
out:
	kfree(data);
	return ret;
}

static int tpu_cord_new_data(struct tpu_cord *cord, struct cord_new_data __user *argp)
{
	struct cord_new_data cmd;
	void *d;
	int tid, ret = 0;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;
	if (cmd.n == 0 || cmd.n > MAX_CMD_N)
		return -EINVAL;

	d = kcalloc(cmd.n, cord->data_width, GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	if (copy_from_user(d, cmd.data, cmd.n * cord->data_width)) {
		ret = -EFAULT;
		goto out;
	}
	ret = tpu_cord_avail_cid(cord);
	if (ret < 0) {
		ret = -EMFILE;
		goto out;
	}
	tid = tpu_new_tree(cord->tdev, cmd.n, cord->data_width, d);
	if (tid < 0) {
		ret = tid;
		goto out;
	}
	tpu_cord_set_map(cord, ret, tid, cmd.n);
out:
	kfree(d);
	return ret;
}

static int tpu_cord_set_data_width(struct tpu_cord *cord, ulong w)
{
	if (w > 8 || w == 0 || (w & -w) != w)
		return -EINVAL;

	cord->data_width = w;
	return 0;
}

static int tpu_cord_delete(struct tpu_cord *cord, u32 cid)
{
	int tid;

	if (!tpu_cord_find_cid(cord, cid, &tid, NULL))
		return -EINVAL;
	tpu_cord_set_map(cord, cid, 0, 0);
	return WARN_ON(tpu_delete(cord->tdev, tid));
}

static int tpu_cord_init(struct tpu_cord *cord)
{
	tpu_cord_set_data_width(cord, 1);
	/* kzalloc already cleared cid_map */
	return 0;
}

static void tpu_cord_release(struct tpu_cord *cord)
{
}

/* file operations */

static long tpu_corddev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct tpu_cord *cord = filp->private_data;
	void __user *argp = (void *)arg;

	switch (cmd) {
	case CORD_GET_DEVICE_VERSION:
		return tpu_hw_version(cord->tdev);
	case CORD_SET_DATA_WIDTH:
		return tpu_cord_set_data_width(cord, arg);
	case CORD_NEW_DATA:
		return tpu_cord_new_data(cord, argp);
	case CORD_DISPLAY:
		return tpu_cord_display(cord, argp);
	case CORD_CUT:
		return tpu_cord_cut(cord, argp);
	case CORD_PASTE:
		return tpu_cord_paste(cord, argp);
	case CORD_DELETE:
		return tpu_cord_delete(cord, (u32)(ulong)argp);
	case CORD_REVERSE:
		return tpu_cord_reverse(cord, argp);
	case CORD_COVER:
		return tpu_cord_cover(cord, argp);
	default:
		return -ENOTTY;
	}
}

static int tpu_corddev_open(struct inode *n, struct file *filp)
{
	struct miscdevice *corddev = filp->private_data;
	struct tpu_cord *cord;
	int ret = 0;

	filp->private_data = NULL;
	mutex_lock(&open_lock);

	if (opening) {
		ret = -EBUSY;
		goto out;
	}
	debug("File opening %llx\n", (u64) corddev);

	cord = kzalloc(sizeof(*cord), GFP_KERNEL);
	if (!cord) {
		ret = -ENOMEM;
		goto out;
	}

	cord->tdev = container_of(corddev, struct tpu_device, corddev);
	tpu_reset(cord->tdev);

	ret = tpu_cord_init(cord);
	if (ret) {
		kfree(cord);
		goto out;
	}

	filp->private_data = cord;
	opening = true;
out:
	mutex_unlock(&open_lock);
	return ret;
}

static int tpu_corddev_release(struct inode *n, struct file *filp)
{
	struct tpu_cord *cord = filp->private_data;

	debug("File releasing %llx\n", (u64) cord);
	if (!cord)
		return 0;
	mutex_lock(&open_lock);

	tpu_cord_release(cord);
	kfree(cord);
	opening = false;

	mutex_unlock(&open_lock);
	return 0;
}

const struct file_operations tpu_cord_ops = {
	.owner = THIS_MODULE,
	.open = tpu_corddev_open,
	.unlocked_ioctl = tpu_corddev_ioctl,
	.llseek = no_llseek,
	.release = tpu_corddev_release,
};
