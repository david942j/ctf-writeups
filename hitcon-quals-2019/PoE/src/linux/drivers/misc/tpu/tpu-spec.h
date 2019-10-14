/*
 * Define TPU Hardware SPEC.
 *
 * Copyright (c) 2019 david942j
 */
#ifndef _TPU_SPEC_H
#define _TPU_SPEC_H

#define PCI_VENDOR_ID_QEMU 0x1234
#define PCI_DEVICE_ID_TPU 0x1337

#define SIZEOF_CSRS 8 * 9
#define SIZEOF_QUEUE (4096)

#define QUEUE_WRAP_BIT (1 << 12)
#define QUEUE_REAL_INDEX(c) (c & (QUEUE_WRAP_BIT - 1))
#define QUEUE_INDEX_MASK (QUEUE_WRAP_BIT * 2 - 1)

enum TPU_CSR {
	TPU_CSR_VERSION,
	TPU_CSR_RESET,
	TPU_CSR_IRQ_STATUS,
	TPU_CSR_CLEAR_IRQ,
	TPU_CSR_CMD_SENT,
	TPU_CSR_CMD_HEAD,
	TPU_CSR_CMD_TAIL,
	TPU_CSR_RSP_HEAD,
	TPU_CSR_RSP_TAIL,
};

#include "tpu-ir.h"

#endif /* _TPU_SPEC_H */
