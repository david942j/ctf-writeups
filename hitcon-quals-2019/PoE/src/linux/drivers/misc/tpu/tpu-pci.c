/*
 * Linux kernel PCI device driver of TPU.
 *
 * Copyright (c) 2019 david942j
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/types.h>

#include "tpu-internal.h"
#include "tpu-spec.h"

static irqreturn_t tpu_irq_handler(int irq, void *data)
{
	int i;
	struct tpu_device *tdev = data;
	struct tpu_rsp_handler *handlers;
	
	tdev->csrs[TPU_CSR_CLEAR_IRQ] = 1;
	debug("IRQ signal received\n");
	spin_lock(&tdev->irq_lock);

	handlers = tdev->rsp_handlers;
	for (i = 0; i < tdev->num_handlers; i++)
		handlers[i].retval = tpu_rsp_handle(tdev, handlers[i].data);
	tdev->irq_handled = 1;
	tdev->num_handlers = 0;
	tdev->rsp_handlers = NULL;

	spin_unlock(&tdev->irq_lock);

	wake_up(&tdev->waitq);

	return IRQ_HANDLED;
}

static int tpu_pci_mem_remap(struct pci_dev *pdev, int bar, unsigned size, phys_addr_t *phys_addr_p, void **mem_p)
{
	phys_addr_t phys_addr;
	struct resource *res;
	void *mem;
	unsigned long flags;

	phys_addr = pci_resource_start(pdev, bar);
	if (!phys_addr) {
		pci_err(pdev, "No resource");
		return -ENODEV;
	}

	res = devm_request_mem_region(&pdev->dev, phys_addr, size,
				      KBUILD_MODNAME);
	if (!res) {
		pci_err(pdev, "Failed to request memory\n");
		return -EBUSY;
	}

	mem = devm_ioremap(&pdev->dev, phys_addr, size);
	if (!mem) {
		pci_err(pdev, "ioremap failed\n");
		return -ENOMEM;
	}

	flags = pci_resource_flags(pdev, bar);
	if (flags & IORESOURCE_IO) {
		pci_err(pdev,
			"IO mapped PCI devices are not supported\n");
		return -ENOTSUPP;
	}

	*phys_addr_p = phys_addr;
	*mem_p = mem;
	return 0;
}

static int tpu_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	struct tpu_device *tdev;

	tdev = devm_kzalloc(&pdev->dev, sizeof(*tdev), GFP_KERNEL);
	if (!tdev)
		return -ENOMEM;
	ret = pci_enable_device(pdev);
	if (ret)
		return ret;

	pci_set_master(pdev);

	ret = tpu_pci_mem_remap(pdev, 0, SIZEOF_CSRS, &tdev->csrs_phys, (void**)&tdev->csrs);
	if (ret)
		goto out_disable;
	ret = tpu_pci_mem_remap(pdev, 1, SIZEOF_QUEUE, &tdev->cmd_queue_phys, (void**)&tdev->cmd_queue);
	if (ret)
		goto out_disable;
	ret = tpu_pci_mem_remap(pdev, 2, SIZEOF_QUEUE, &tdev->rsp_queue_phys, (void**)&tdev->rsp_queue);
	if (ret)
		goto out_disable;
	ret = tpu_pci_mem_remap(pdev, 3, SIZEOF_QUEUE, &tdev->data_phys, &tdev->data);
	if (ret)
		goto out_disable;

	tdev->dev = &pdev->dev;
	ret = request_irq(pdev->irq, tpu_irq_handler, IRQF_SHARED, "tpu-pci", tdev);
	if (ret) {
		pci_err(pdev, "Failed to request interrupt IRQ: %d\n", pdev->irq);
		goto out_disable;
	}

	ret = tpu_init(tdev);
	if (ret) {
		free_irq(pdev->irq, tdev);
		goto out_disable;
	}

	pci_set_drvdata(pdev, tdev);

	return 0;
out_disable:
	pci_disable_device(pdev);
	return ret;
}

static void tpu_pci_remove(struct pci_dev *pdev)
{
	struct tpu_device *tdev = pci_get_drvdata(pdev);

	tpu_exit(tdev);
	free_irq(pdev->irq, tdev);
	pci_disable_device(pdev);
}

static const struct pci_device_id tpu_pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_QEMU, PCI_DEVICE_ID_TPU) },
	{ 0 },
};

MODULE_DEVICE_TABLE(pci, tpu_pci_ids);
static struct pci_driver tpu_pci_driver = {
	.name = "tpu-pci",
	.id_table = tpu_pci_ids,
	.probe = tpu_pci_probe,
	.remove = tpu_pci_remove,
};
module_pci_driver(tpu_pci_driver);

MODULE_AUTHOR("david942j @ 217");
MODULE_LICENSE("GPL");
