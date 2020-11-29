/*
 * File system interface handlers for SPARK.
 *
 * Copyright (c) 2020 david942j
 */

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <uapi/linux/spark.h>

#include "spark-internal.h"

static const struct file_operations node_fops;

static int node_ioctl_query(struct spark_node *node, struct spark_ioctl_query __user *arg)
{
  struct spark_ioctl_query qry;
  struct file *filp1 = NULL, *filp2 = NULL;
  int ret = -EINVAL;
  long long ans;
  struct spark_node *a, *b;

  /* prevent node being freed */
  spark_node_get(node);
  if (!node->graph)
    goto putnode;
  if (copy_from_user(&qry, arg, sizeof(qry))) {
    ret = -EFAULT;
    goto putnode;
  }
  filp1 = fget(qry.fd1);
  if (!filp1) {
    ret = -EBADF;
    goto putnode;
  }
  if (filp1->f_op != &node_fops)
    goto put1;
  filp2 = fget(qry.fd2);
  if (!filp2) {
    ret = -EBADF;
    goto put1;
  }
  if (filp2->f_op != &node_fops)
    goto put2;
  a = filp1->private_data;
  b = filp2->private_data;
  /* if a and/or b doesn't belong to @node, we shall just return a wrong distance */
  ans = spark_graph_query(node->graph, a->idx, b->idx);
  if (ans < 0) {
    ret = (int) ans;
    goto put2;
  }
  qry.distance = ans;
  if (copy_to_user(arg, &qry, sizeof(qry)))
    ret = -EFAULT;
  else
    ret = 0;
put2:
  fput(filp2);
put1:
  fput(filp1);
putnode:
  spark_node_put(node);
  return ret;
}

static int node_ioctl_info(struct spark_node *node, struct spark_ioctl_info __user *arg)
{
  struct spark_ioctl_info info = {};

  spark_node_get_info(node, &info);
  if (copy_to_user(arg, &info, sizeof(info)))
    return -EFAULT;
  return 0;
}

static int node_ioctl_link(struct spark_node *node, int fd, unsigned int w)
{
  struct file *filp = fget(fd);
  struct spark_node *other;
  int ret = -EINVAL;

  if (!filp)
    return -EBADF;
  if (filp->f_op != &node_fops)
    goto out;
  other = filp->private_data;
  ret = spark_node_link(node, other, w);
out:
  fput(filp);
  return ret;
}

static long node_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  struct spark_node *node = filp->private_data;

  switch (cmd) {
  case SPARK_LINK:
    return node_ioctl_link(node, arg & 0xffffffffu, arg >> 32);
  case SPARK_INFO:
    return node_ioctl_info(node, (void*)arg);
  case SPARK_FINALIZE:
    return spark_node_finalize(node);
  case SPARK_QUERY:
    return node_ioctl_query(node, (void*)arg);
  default:
    return -ENOTTY;
  };
}

static int node_open(struct inode *inodep, struct file *filp)
{
  struct spark_node *node = spark_node_alloc();

  if (IS_ERR(node))
    return PTR_ERR(node);
  filp->private_data = node;
  return 0;
}

static int node_release(struct inode *inodep, struct file *filp)
{
  struct spark_node *node = filp->private_data;

  spark_node_free(node);
  return 0;
}

static const struct file_operations node_fops = {
  .owner = THIS_MODULE,
  /* .read = node_read, */
  /* .write = node_write, */
  .open = node_open,
  .release = node_release,
  .unlocked_ioctl = node_ioctl,
  .llseek = no_llseek,
};

static struct miscdevice node_device = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "node",
  .fops = &node_fops,
};

static int __init spark_init(void)
{
  debug("offsetof(idx) = 0x%lx", offsetof(struct spark_node, idx));
  return misc_register(&node_device);
}

static void __exit spark_exit(void)
{
  misc_deregister(&node_device);
}

module_init(spark_init);
module_exit(spark_exit);
MODULE_AUTHOR("david942j @ 217");
MODULE_LICENSE("GPL");
