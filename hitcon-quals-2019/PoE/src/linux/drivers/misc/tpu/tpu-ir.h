/*
 * Shared file for TPU intermediate representation.
 *
 * Copyright (c) 2019 david942j
 */
#ifndef _TPU_IR_H
#define _TPU_IR_H

/* IR registers */
enum TPU_REG {
	TPU_R0 = 0,
	TPU_R1 = 1,
	TPU_R2 = 2,

	TPU_REG_END = 16,
};

enum TPU_OP {
	TPU_OP_NEW,
	TPU_OP_SPLIT,
	TPU_OP_MERGE,
	TPU_OP_PRINT,
	TPU_OP_INFO,
	TPU_OP_DELETE,
	TPU_OP_REVERSE,
	TPU_OP_COVER,
	TPU_OP_VERSION,
	TPU_OP_LOAD,

	TPU_OP_END = 16,
};

typedef unsigned long long cmd_type;

struct cmd_element {
	unsigned char count;
	cmd_type inst[];
} __attribute__((packed));

#endif /* _TPU_IR_H */
