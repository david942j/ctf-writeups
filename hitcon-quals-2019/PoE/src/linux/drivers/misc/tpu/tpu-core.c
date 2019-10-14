/*
 * Core functions for TPU driver.
 *
 * Copyright (c) 2019 david942j
 */

#include "tpu-cord.h"
#include "tpu-internal.h"
#include "tpu-spec.h"

void tpu_reset(struct tpu_device *tdev)
{
	tdev->csrs[TPU_CSR_RESET] = 1;
	tdev->cmd_tail = 0;
	tdev->rsp_head = 0;
}

int tpu_init(struct tpu_device *tdev)
{
	int ret;

	tdev->corddev.minor = MISC_DYNAMIC_MINOR;
	tdev->corddev.name = "cord";
	tdev->corddev.fops = &tpu_cord_ops;
	ret = misc_register(&tdev->corddev);
	if (ret) {
		dev_err(tdev->dev, "device cord register failed");
		return ret;
	}
	mutex_init(&tdev->command_lock);
	spin_lock_init(&tdev->irq_lock);
	init_waitqueue_head(&tdev->waitq);

	return 0;
}

void tpu_exit(struct tpu_device *tdev)
{
	misc_deregister(&tdev->corddev);
}
