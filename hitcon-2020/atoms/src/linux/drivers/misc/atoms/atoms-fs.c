/*
 * File system interface handlers for ATOMS.
 *
 * Copyright (c) 2020 david942j
 */

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <uapi/linux/atoms.h>

#include "atoms-internal.h"

static const struct file_operations atoms_fops;

struct atoms_mem;

struct atoms_client {
  spinlock_t mem_lock;
  struct atoms_mem *mem;
};

static vm_fault_t atoms_mmap_fault(struct vm_fault *vmf)
{
  struct atoms_mem *mem = vmf->vma->vm_private_data;
  struct page *page = atoms_mem_page_at(mem, vmf->pgoff);

  if (!page)
    return VM_FAULT_SIGSEGV;
  vmf->page = page;
  get_page(page);

  return 0;
}

static void vm_close(struct vm_area_struct *vma)
{
  atoms_mem_put(vma->vm_private_data);
  debug("%s", __func__);
}

static void vm_open(struct vm_area_struct *vma)
{
  debug("%s", __func__);
}

static const struct vm_operations_struct atoms_vm_ops = {
    .fault = atoms_mmap_fault,
    .open = vm_open,
    .close = vm_close,
};

static int atoms_mmap(struct file *filp, struct vm_area_struct *vma)
{
  struct atoms_client *client = filp->private_data;
  int ret = 0;

  spin_lock(&client->mem_lock);
  if (!client->mem) {
    ret = -ENODEV;
    goto out;
  }
  vma->vm_private_data = atoms_mem_get(client->mem);
  vma->vm_ops = &atoms_vm_ops;

out:
  spin_unlock(&client->mem_lock);
  return ret;
}

static struct atoms_client *atoms_client_alloc(void)
{
  struct atoms_client *client = kzalloc(sizeof(*client), GFP_KERNEL);

  if (!client)
    return ERR_PTR(-ENOMEM);
  spin_lock_init(&client->mem_lock);
  return client;
}

static void atoms_client_free(struct atoms_client *client)
{
  spin_lock(&client->mem_lock);
  atoms_mem_put(client->mem);
  spin_unlock(&client->mem_lock);
  kfree(client);
}

static bool check_mem(struct atoms_client *client, unsigned int cmd)
{
  if (cmd == ATOMS_INFO)
    return true;
  if (cmd == ATOMS_USE_TOKEN)
    return !client->mem;
  return !!client->mem;
}

static int atoms_ioctl_use_token(struct atoms_client *client, unsigned long long token)
{
  struct atoms_mem *mem;

  if (token == 0)
    return -EINVAL;

  mem = atoms_mem_create_or_find_by_token(token);

  /* failed to create */
  if (!mem)
    return -ENOMEM;
  client->mem = mem;
  return 0;
}

static int atoms_ioctl_info(struct atoms_mem *mem,
                            struct atoms_ioctl_info __user *arg)
{
  struct atoms_ioctl_info info = {};

  if (mem)
    atoms_mem_info(mem, &info.token, &info.num_pages, &info.num_segments);
  if (copy_to_user(arg, &info, sizeof(info)))
    return -EFAULT;
  return 0;
}

static int atoms_ioctl_alloc(struct atoms_mem *mem,
                             struct atoms_ioctl_alloc __user *arg)
{
  struct atoms_ioctl_alloc parm;
  size_t offset;
  int ret;

  if (copy_from_user(&parm, arg, sizeof(parm)))
    return -EFAULT;
  ret = atoms_mem_alloc(mem, parm.size, &offset);
  if (ret)
    return ret;
  parm.offset = offset;
  if (copy_to_user(arg, &parm, sizeof(parm)))
    return -EFAULT;
  return 0;
}

static long atoms_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  struct atoms_client *client = filp->private_data;
  int ret = -EINVAL;

  spin_lock(&client->mem_lock);
  if (!check_mem(client, cmd))
    goto out;
  switch (cmd) {
  case ATOMS_USE_TOKEN:
    ret = atoms_ioctl_use_token(client, arg);
    break;
  case ATOMS_INFO:
    ret = atoms_ioctl_info(client->mem, (void*)arg);
    break;
  case ATOMS_ALLOC:
    ret = atoms_ioctl_alloc(client->mem, (void*)arg);
    break;
  case ATOMS_RELEASE:
    atoms_mem_remove_from_pool(client->mem);
    ret = 0;
    break;
  default:
    return -ENOTTY;
  };
out:
  spin_unlock(&client->mem_lock);
  return ret;
}

static int atoms_open(struct inode *inodep, struct file *filp)
{
  struct atoms_client *client = atoms_client_alloc();

  if (IS_ERR(client))
    return PTR_ERR(client);
  filp->private_data = client;
  return 0;
}

static int atoms_release(struct inode *inodep, struct file *filp)
{
  struct atoms_client *client = filp->private_data;

  atoms_client_free(client);
  return 0;
}

static const struct file_operations atoms_fops = {
  .owner = THIS_MODULE,
  .open = atoms_open,
  .release = atoms_release,
  .unlocked_ioctl = atoms_ioctl,
  .mmap = atoms_mmap,
  .llseek = no_llseek,
};

static struct miscdevice node_device = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "atoms",
  .fops = &atoms_fops,
};

static int __init atoms_init(void)
{
  return misc_register(&node_device);
}

static void __exit atoms_exit(void)
{
  misc_deregister(&node_device);
}

module_init(atoms_init);
module_exit(atoms_exit);
MODULE_AUTHOR("david942j @ 217");
MODULE_LICENSE("GPL");
