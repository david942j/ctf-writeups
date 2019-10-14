/*
 * Treap Processing Unit
 *
 * Copyright (c) 2019 david942j
 */

#include "qemu/osdep.h"

#include "hw/pci/pci.h"
#include "qemu/module.h"
#include "qemu/units.h"

#include "tpu-ir.h"

/* #define DDD */

#ifdef DDD
 #define debug(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
 #define debug(format, ...)
#endif /* DDD */

#define PCI_DEVICE_ID_TPU 0x1337
#define TPU_DEVICE_NAME "tpu"
#define TPU(obj) OBJECT_CHECK(TPUState, obj, TPU_DEVICE_NAME)

#define QUEUE_SIZE (1 << 12)
#define QUEUE_WRAP_BIT (1 << 12)
#define QUEUE_REAL_INDEX(c) (c & (QUEUE_WRAP_BIT - 1))
#define QUEUE_INDEX_MASK (QUEUE_WRAP_BIT * 2 - 1)

#define MAX_CMD_N 255

struct Csrs {
	uint64_t version; /* R */
	uint64_t reset; /* W */
	uint64_t irq_status; /* R */
	uint64_t clear_irq; /* W */
	uint64_t cmd_sent; /* W */
	uint64_t cmd_head; /* R */
	uint64_t cmd_tail; /* W */
	uint64_t rsp_head; /* W */
	uint64_t rsp_tail; /* R */
	uint64_t reserved[7];
};

typedef struct Node {
	struct Node *l, *r;
	uint64_t hval;
	int w;
	int sz;
	bool alive;
	uint64_t data;
	int tid, idx;
	bool rev;
	bool covered;
	uint64_t cover_val;
} Node;

typedef struct {
	PCIDevice pdev;
	MemoryRegion mem_csrs, mem_cmd_queue, mem_rsp_queue, mem_data;
	QemuThread thread;
	QemuMutex thr_lock;
	bool stop;
	struct Csrs csrs;
	uint8_t *cmd_queue, *rsp_queue, *data;

	/* TPU VM */
	Node* reg[TPU_REG_END];
} TPUState;

// {{{ err macros
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}
// }}}

// {{{ Treap operations

#define MAX_NODE_NUM (100000)
static int total_cnt = 0;
static Node *pool[MAX_NODE_NUM];

static uint64_t seed = 0x32f1ac98b15fbacdull;

static uint64_t rand64(void)
{
	seed = seed * 0x139d21737 + 0xdeadface3199ef33ull;
	return seed;
}

static inline void mark_rev(Node *n)
{
	if (n)
		n->rev ^= 1;
}

static inline void mark_cover(Node *n, uint64_t val)
{
	if (!n)
		return;
	n->covered = true;
	n->cover_val = val;
}

static void push(Node *n)
{
	if (n->rev) {
		Node *tmp = n->l;

		n->l = n->r; n->r = tmp;
		mark_rev(n->l);
		mark_rev(n->r);
		n->rev = false;
	}
	if (n->covered) {
		mark_cover(n->l, n->cover_val);
		mark_cover(n->r, n->cover_val);
		n->covered = false;
		n->data = n->cover_val;
	}
}

static void pull(Node *n)
{
	int s = 1;
	if (n->l) s += n->l->sz;
	if (n->r) s += n->r->sz;

	n->sz = s;
}

static inline void dump_tree(Node *n)
{
	if (!n)
		return;
	dump_tree(n->l);
	debug("%s: %d %d %lx %lx\n", __func__, n->tid, n->idx, n->data, n->hval);
	dump_tree(n->r);
}

static void print_tree(Node *n, void *data, int *cnt)
{
	if (!n)
		return;
	push(n);

	print_tree(n->l, data, cnt);
	memcpy(data + (*cnt), &n->data, n->w);
	(*cnt) += n->w;
	print_tree(n->r, data, cnt);

	pull(n);
}

// recursively
// TODO: check if depth MAX_NODE_NUM is fine.. or use a stack for *all* recursive functions
static void dead_tree(Node *n)
{
	if (!n)
		return;
	debug("%s: %p %d %d\n", __func__, n, n->tid, n->idx);
	dead_tree(n->l);
	dead_tree(n->r);
	n->alive = false;
	n->tid = -1;
}

static void clear_pool(void)
{
	int i;

	debug("%s: clearing %d nodes\n", __func__, total_cnt);
	for (i = 0; i < total_cnt; i++) {
		if (pool[i]) {
			g_free(pool[i]);
			pool[i] = NULL;
		}
	}
	total_cnt = 0;
}

static Node *new_node(int w, void *data)
{
	g_assert(total_cnt < MAX_NODE_NUM);
	Node *n = g_malloc0(sizeof(*n));

	n->w = w;
	memcpy(&n->data, data, w);
	n->l = n->r = NULL;
	/* new node has an invalid tid by default */
	n->tid = -1;
	n->hval = rand64();
	n->sz = 1;
	n->idx = total_cnt;
	n->alive = true;
	pool[total_cnt++] = n;

	return n;
}

static Node *merge(Node *a, Node *b)
{
	if (a == NULL)
		return b;
	if (b == NULL)
		return a;
	if (a->hval >= b->hval) {
		push(a);
		a->r = merge(a->r, b);
		pull(a);
		return a;
	}
	else {
		push(b);
		b->l = merge(a, b->l);
		pull(b);
		return b;
	}
}

static void split(Node *now, uint32_t x, Node **a, Node **b)
{
	int lsz;

	if (x == 0) {
		*a = NULL;
		*b = now;
		return;
	}
	if (now == NULL || now->sz == x) {
		*a = now;
		*b = NULL;
		return;
	}

	push(now);

	if (now->l) lsz = now->l->sz;
	else lsz = 0;

	if(lsz + 1 <= x) {
		*a = now;
		split(now->r, x - lsz - 1, &((*a)->r), b);
	}
	else {
		*b = now;
		split(now->l, x, a, &((*b)->l));
	}
	pull(now);
}

static Node *create_tree(int n, int w, void *data)
{
	Node *a = NULL;
	int i;

	for (i = 0; i < n; i++)
		a = merge(a, new_node(w, data + i * w));

	g_assert(a->sz == n);
	/* dump_tree(pool[a->idx]); */
	return a;
}
// }}}

static inline bool is_root(Node *n)
{
	return n && !IS_ERR(n) && n->alive && n->tid == n->idx;
}

static inline bool null_or_root(Node *n)
{
	return !n || is_root(n);
}

static inline void unset_tid(Node *n)
{
	if (n)
		n->tid = -1;
}

static inline void set_tid(Node *n)
{
	if (n)
		n->tid = n->idx;
}

static void push_rsp(TPUState *tpu, uint8_t *rsp, uint32_t n)
{
	uint64_t head = tpu->csrs.rsp_head, tail = tpu->csrs.rsp_tail;
	uint32_t i;

	for (i = 0; i < n; i++) {
		g_assert((head ^ tail) != QUEUE_WRAP_BIT); // crash if rsp queue is full
		tpu->rsp_queue[QUEUE_REAL_INDEX(tail)] = rsp[i];
		tail = (tail + 1) & QUEUE_INDEX_MASK;
	}
	tpu->csrs.rsp_tail = tail;
	debug("%s: pushed %u bytes\n", __func__, n);
}

static void handle_cmd_version(TPUState *tpu)
{
	uint8_t rsp[3];
	rsp[0] = TPU_OP_VERSION;
	rsp[1] = 1;
	rsp[2] = 217;
	push_rsp(tpu, rsp, 3);
}

static void handle_cmd_new(TPUState *tpu, cmd_type inst)
{
	int r = (inst >> 4) & (TPU_REG_END - 1);
	int w = (inst >> 8) & 0xf;
	uint32_t n = (inst >> 12) & (0xffffffffu);

	if (n == 0 || n > MAX_CMD_N || (w != 1 && w != 2 && w != 4 && w != 8)) {
		tpu->reg[r] = ERR_PTR(-EINVAL);
		return;
	}
	tpu->reg[r] = create_tree(n, w, tpu->data);
	/* only root node can have a valid tid */
	set_tid(tpu->reg[r]);
	debug("%s: tid = %d\n", __func__, tpu->reg[r]->tid);
}

/* convert Node * -> tid */
static void handle_cmd_info(TPUState *tpu, cmd_type inst)
{
	int tid = -EINVAL;
	Node *node = tpu->reg[(inst >> 4) & (TPU_REG_END - 1)];
	uint8_t op = TPU_OP_INFO;

	if (!node)
		tid = -EINVAL;
	else if (IS_ERR(node))
		tid = PTR_ERR(node);
	else if (is_root(node))
		tid = node->tid;

	push_rsp(tpu, &op, 1);
	push_rsp(tpu, (uint8_t *)&tid, 4);
}

static void handle_cmd_load(TPUState *tpu, cmd_type inst)
{
	uint64_t ii = inst >> 4;
	uint8_t r = ii & (TPU_REG_END - 1);
	uint32_t tid = (ii >> 4) & 0xffffffffu;
	Node *n = NULL;

	debug("%s: tid = %u\n", __func__, tid);
	if (tid < MAX_NODE_NUM && is_root(pool[tid]))
		n = pool[tid];
#ifdef DDD
	else
		g_assert(false);
#endif
	debug("%s: set R%u to %p\n", __func__, r, n);
	tpu->reg[r] = n;
}

static void handle_cmd_merge(TPUState *tpu, cmd_type inst)
{
	uint64_t ii = inst >> 4;
	uint8_t d, s1, s2;

	d = ii & (TPU_REG_END - 1); ii >>= 4;
	s1 = ii & (TPU_REG_END - 1); ii >>= 4;
	s2 = ii & (TPU_REG_END - 1);

	if (is_root(tpu->reg[s1]) && is_root(tpu->reg[s2]) &&
	    tpu->reg[s1]->w != tpu->reg[s2]->w) {
		tpu->reg[d] = NULL;
		return;
	}

	if (null_or_root(tpu->reg[s1]) && null_or_root(tpu->reg[s2])) {
		unset_tid(tpu->reg[s1]);
		unset_tid(tpu->reg[s2]);
		tpu->reg[d] = merge(tpu->reg[s1], tpu->reg[s2]);
		set_tid(tpu->reg[d]);
	}
	else {
		tpu->reg[d] = NULL;
	}
}

static void handle_cmd_split(TPUState *tpu, cmd_type inst)
{
	uint64_t ii = inst >> 4;
	uint8_t s, d1, d2;
	uint32_t x;

	s = ii & (TPU_REG_END - 1); ii >>= 4;
	x = ii & 0xffffffffu; ii >>= 32;
	d1 = ii & (TPU_REG_END - 1); ii >>= 4;
	d2 = ii & (TPU_REG_END - 1);

	if (!is_root(tpu->reg[s])) {
		debug("%s: wtf\n", __func__);
		tpu->reg[d1] = NULL;
		tpu->reg[d2] = NULL;
		return;
	}
	debug("%s: split x=%u, %u (%p) to %u, %u\n", __func__, x, s, tpu->reg[s], d1, d2);
	unset_tid(tpu->reg[s]);
	split(tpu->reg[s], x, &tpu->reg[d1], &tpu->reg[d2]);
	set_tid(tpu->reg[d1]);
	set_tid(tpu->reg[d2]);
	debug("%s: after split %u: %p, %u: %p\n", __func__, d1, tpu->reg[d1], d2, tpu->reg[d2]);
}

static void handle_cmd_print(TPUState *tpu, cmd_type inst)
{
	Node *n = tpu->reg[(inst >> 4) & (TPU_REG_END - 1)];
	uint8_t op = TPU_OP_PRINT;
	int sz;
	void *data;

	push_rsp(tpu, &op, 1);
	if (!is_root(n) || n->sz > MAX_CMD_N) { /* in case the host is cheating us */
		sz = 0;
		push_rsp(tpu, (uint8_t *)&sz, 1);
	}
	else {
		data = g_malloc(n->sz * n->w);
		sz = 0;
		print_tree(n, data, &sz);
		push_rsp(tpu, (uint8_t *)&n->sz, 1);
		push_rsp(tpu, data, n->sz * n->w);
#ifdef DDD
		g_assert(n->sz * n->w == sz);
#endif
		g_free(data);
	}
}

static void handle_cmd_delete(TPUState *tpu, cmd_type inst)
{
	Node *n = tpu->reg[(inst >> 4) & (TPU_REG_END - 1)];

	if (!is_root(n))
		return;
	dead_tree(n);
}

static void handle_cmd_reverse(TPUState *tpu, cmd_type inst)
{
	Node *n = tpu->reg[(inst >> 4) & (TPU_REG_END - 1)];

	if (!is_root(n))
		return;
	mark_rev(n);
}

static void handle_cmd_cover(TPUState *tpu, cmd_type inst, uint64_t val)
{
	Node *n = tpu->reg[(inst >> 4) & (TPU_REG_END - 1)];

	if (!is_root(n))
		return;
	mark_cover(n, val);
}

static void handle_commands(TPUState *tpu, uint8_t n, cmd_type *insts)
{
	uint8_t op, i;

	memset(&tpu->reg, 0, sizeof(tpu->reg));

	for (i = 0; i < n; i++) {
		op = insts[i] & (TPU_OP_END - 1);
		debug("%s: i = %u, op = %u, r0 = %p\n", __func__, i, op, tpu->reg[0]);
		switch (op) {
		case TPU_OP_VERSION:
			handle_cmd_version(tpu);
			break;
		case TPU_OP_NEW:
			handle_cmd_new(tpu, insts[i]);
			break;
		case TPU_OP_INFO:
			handle_cmd_info(tpu, insts[i]);
			break;
		case TPU_OP_MERGE:
			handle_cmd_merge(tpu, insts[i]);
			break;
		case TPU_OP_LOAD:
			handle_cmd_load(tpu, insts[i]);
			break;
		case TPU_OP_SPLIT:
			handle_cmd_split(tpu, insts[i]);
			break;
		case TPU_OP_PRINT:
			handle_cmd_print(tpu, insts[i]);
			break;
		case TPU_OP_DELETE:
			handle_cmd_delete(tpu, insts[i]);
			break;
		case TPU_OP_COVER:
			if (i + 1 < n) {
				handle_cmd_cover(tpu, insts[i], insts[i + 1]);
				i++;
			}
			break;
		case TPU_OP_REVERSE:
			handle_cmd_reverse(tpu, insts[i]);
			break;
		default:
			break;
		}
	}
}

/* caller holds thr_lock */
static void fetch_and_handle_command(TPUState *tpu)
{
	uint64_t head = tpu->csrs.cmd_head, tail = tpu->csrs.cmd_tail;
	uint8_t cmd_len = tpu->cmd_queue[QUEUE_REAL_INDEX(head)];
	int i, sz = cmd_len * sizeof(cmd_type);
	uint8_t *insts = g_malloc(sz);

	head = (head + 1) & QUEUE_INDEX_MASK;
	for (i = 0; i < sz; i++) {
		g_assert(head != tail); // cmd queue corrupted
		insts[i] = tpu->cmd_queue[QUEUE_REAL_INDEX(head)];
		head = (head + 1) & QUEUE_INDEX_MASK;
	}
	tpu->csrs.cmd_head = head;
	debug("%s: %d instructions fetched.\n", __func__, cmd_len);
	handle_commands(tpu, cmd_len, (cmd_type *)insts);
	g_free(insts);
}

#define THR_LOCK(statement) do { \
  qemu_mutex_lock(&tpu->thr_lock); \
  statement; \
  qemu_mutex_unlock(&tpu->thr_lock); \
} while (0)

static void tpu_init_csrs(struct Csrs *csrs)
{
	memset(csrs, 0, sizeof(*csrs));
	csrs->version = (217 << 8) + 1;
}

/* caller holds thr_lock */
static void tpu_raise_irq(TPUState *tpu)
{
	tpu->csrs.irq_status = 1;
	pci_set_irq(&tpu->pdev, 1);
}

/* caller holds thr_lock */
static void tpu_lower_irq(TPUState *tpu)
{
	tpu->csrs.irq_status = 0;
	pci_set_irq(&tpu->pdev, 0);
}

/* caller holds thr_lock */
static void tpu_reset(TPUState *tpu)
{
	debug("%s\n", __func__);
	tpu_init_csrs(&tpu->csrs);
	tpu_lower_irq(tpu);
	clear_pool();
	seed = 0x32f1ac98b15fbacdull;
}

static void *tpu_main_thread(void *opaque)
{
	TPUState *tpu = opaque;

	while (1) {
		qemu_mutex_lock(&tpu->thr_lock);
		if (tpu->stop) {
			qemu_mutex_unlock(&tpu->thr_lock);
			break;
		}

		if (tpu->csrs.cmd_sent) {
			tpu->csrs.cmd_sent = 0;
			fetch_and_handle_command(tpu);
			tpu_raise_irq(tpu);
		}
		qemu_mutex_unlock(&tpu->thr_lock);
		usleep(10);
	}

	return NULL;
}

static void tpu_init(TPUState *tpu)
{
	qemu_mutex_init(&tpu->thr_lock);
	tpu->stop = false;
	tpu_init_csrs(&tpu->csrs);
	tpu->cmd_queue = g_malloc0(QUEUE_SIZE);
	tpu->rsp_queue = g_malloc0(QUEUE_SIZE);
	tpu->data = g_malloc0(QUEUE_SIZE);

	qemu_thread_create(&tpu->thread, "tpu", tpu_main_thread, tpu,
			   QEMU_THREAD_JOINABLE);
}

static uint64_t tpu_csr_read(void *opaque, hwaddr addr, unsigned size)
{
	TPUState *tpu = opaque;
	uint64_t val = 0;

	switch (addr) {
	case offsetof(struct Csrs, version):
		THR_LOCK(val = tpu->csrs.version);
		break;
	case offsetof(struct Csrs, irq_status):
		THR_LOCK(val = tpu->csrs.irq_status);
		break;
	case offsetof(struct Csrs, cmd_head):
		debug("cmd_head - ");
		THR_LOCK(val = tpu->csrs.cmd_head);
		break;
	case offsetof(struct Csrs, rsp_tail):
		debug("rsp_tail - ");
		THR_LOCK(val = tpu->csrs.rsp_tail);
		break;
	default:
		return 0;
	}

	debug("%s: addr: %#lx, size: %u, val: %#lx\n", __func__, addr, size, val);
	return val;
}

static void tpu_csr_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
	TPUState *tpu = opaque;

	switch (addr) {
	case offsetof(struct Csrs, reset):
		THR_LOCK(tpu_reset(tpu));
		break;
	case offsetof(struct Csrs, clear_irq):
		THR_LOCK(tpu_lower_irq(tpu));
		break;
	case offsetof(struct Csrs, cmd_sent):
		THR_LOCK(tpu->csrs.cmd_sent = !!val);
		break;
	case offsetof(struct Csrs, cmd_tail):
		debug("cmd_tail - ");
		THR_LOCK(tpu->csrs.cmd_tail = val & QUEUE_INDEX_MASK);
		break;
	case offsetof(struct Csrs, rsp_head):
		debug("rsp_head - ");
		THR_LOCK(tpu->csrs.rsp_head = val & QUEUE_INDEX_MASK);
		break;
	default:
		return;
	}

	debug("%s: addr: %#lx, size: %u, val: %#lx\n", __func__, addr, size, val);
}

static void tpu_cmd_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
	TPUState *tpu = opaque;

	switch (size) {
	case 1:
		THR_LOCK(*((uint8_t*)(tpu->cmd_queue + addr)) = val);
		break;
	case 2:
		THR_LOCK(*((uint16_t*)(tpu->cmd_queue + addr)) = val);
		break;
	case 4:
		THR_LOCK(*((uint32_t*)(tpu->cmd_queue + addr)) = val);
		break;
	case 8:
		THR_LOCK(*((uint64_t*)(tpu->cmd_queue + addr)) = val);
		break;
	default:
		return;
	}

	debug("%s: addr: %#lx, size: %u, val: %#lx\n", __func__, addr, size, val);
}

static uint64_t tpu_rsp_read(void *opaque, hwaddr addr, unsigned size)
{
	uint64_t val = 0;
	TPUState *tpu = opaque;

	switch (size) {
	case 1:
		THR_LOCK(val = *((uint8_t*)(tpu->rsp_queue + addr)));
		break;
	case 2:
		THR_LOCK(val = *((uint16_t*)(tpu->rsp_queue + addr)));
		break;
	case 4:
		THR_LOCK(val = *((uint32_t*)(tpu->rsp_queue + addr)));
		break;
	case 8:
		THR_LOCK(val = *((uint64_t*)(tpu->rsp_queue + addr)));
		break;
	default:
		return 0;
	}

	debug("%s: addr: %#lx, size: %u, val: %#lx\n", __func__, addr, size, val);
	return val;
}

static void tpu_data_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
	TPUState *tpu = opaque;

	switch (size) {
	case 1:
		THR_LOCK(*((uint8_t*)(tpu->data + addr)) = val);
		break;
	case 2:
		THR_LOCK(*((uint16_t*)(tpu->data + addr)) = val);
		break;
	case 4:
		THR_LOCK(*((uint32_t*)(tpu->data + addr)) = val);
		break;
	case 8:
		THR_LOCK(*((uint64_t*)(tpu->data + addr)) = val);
		break;
	default:
		return;
	}

	debug("%s: addr: %#lx, size: %u, val: %#lx\n", __func__, addr, size, val);
}

static uint64_t noop(void)
{
	debug("%s\n", __func__);
	return 0;
}

static const MemoryRegionOps tpu_mem_csrs_ops = {
	.read = tpu_csr_read,
	.write = tpu_csr_write,
	.valid = {
		.min_access_size = 8,
		.max_access_size = 8,
	},
	.impl = {
		.min_access_size = 8,
		.max_access_size = 8,
	},
};

static const MemoryRegionOps tpu_mem_cmd_queue_ops = {
	.read = (typeof(((MemoryRegionOps*)0)->read))noop,
	.write = tpu_cmd_write,
	.valid = {
		.min_access_size = 1,
		.max_access_size = 8,
	},
	.impl = {
		.min_access_size = 1,
		.max_access_size = 8,
	},
};

static const MemoryRegionOps tpu_mem_rsp_queue_ops = {
	.read = tpu_rsp_read,
	.write = (typeof(((MemoryRegionOps*)0)->write))noop,
	.valid = {
		.min_access_size = 1,
		.max_access_size = 8,
	},
	.impl = {
		.min_access_size = 1,
		.max_access_size = 8,
	},
};

static const MemoryRegionOps tpu_mem_data_ops = {
	.read = (typeof(((MemoryRegionOps*)0)->read))noop,
	.write = tpu_data_write,
	.valid = {
		.min_access_size = 1,
		.max_access_size = 8,
	},
	.impl = {
		.min_access_size = 1,
		.max_access_size = 8,
	},
};

static void tpu_realize(PCIDevice *dev, Error **errp)
{
	TPUState *tpu = TPU(dev);
	uint8_t *config = dev->config;

	pci_config_set_interrupt_pin(config, 1);

	memory_region_init_io(&tpu->mem_csrs, OBJECT(tpu), &tpu_mem_csrs_ops, tpu, "tpu-csr", sizeof(struct Csrs));
	pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &tpu->mem_csrs);

	memory_region_init_io(&tpu->mem_cmd_queue, OBJECT(tpu), &tpu_mem_cmd_queue_ops, tpu, "tpu-cmd", QUEUE_SIZE);
	pci_register_bar(dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &tpu->mem_cmd_queue);
	memory_region_init_io(&tpu->mem_rsp_queue, OBJECT(tpu), &tpu_mem_rsp_queue_ops, tpu, "tpu-rsp", QUEUE_SIZE);
	pci_register_bar(dev, 2, PCI_BASE_ADDRESS_SPACE_MEMORY, &tpu->mem_rsp_queue);

	memory_region_init_io(&tpu->mem_data, OBJECT(tpu), &tpu_mem_data_ops, tpu, "tpu-data", QUEUE_SIZE);
	pci_register_bar(dev, 3, PCI_BASE_ADDRESS_SPACE_MEMORY, &tpu->mem_data);

	tpu_init(tpu);
}

static void tpu_exit(PCIDevice *dev)
{
	TPUState *tpu = TPU(dev);

	qemu_mutex_lock(&tpu->thr_lock);
	tpu->stop = true;
	qemu_mutex_unlock(&tpu->thr_lock);
	qemu_thread_join(&tpu->thread);
	qemu_mutex_destroy(&tpu->thr_lock);
}

static void tpu_instance_init(Object *obj)
{
}

static void tpu_class_init(ObjectClass *class, void *data)
{
	DeviceClass *dc = DEVICE_CLASS(class);
	PCIDeviceClass *pdc = PCI_DEVICE_CLASS(class);

	pdc->realize = tpu_realize;
	pdc->exit = tpu_exit;
	pdc->vendor_id = PCI_VENDOR_ID_QEMU;
	pdc->device_id = PCI_DEVICE_ID_TPU;
	pdc->revision = 1;
	pdc->class_id = PCI_CLASS_OTHERS;
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static void tpu_register_types(void)
{
	static InterfaceInfo interfaces[] = {
		{ INTERFACE_CONVENTIONAL_PCI_DEVICE },
		{ },
	};
	static const TypeInfo tpu_info = {
		.name = TPU_DEVICE_NAME,
		.parent = TYPE_PCI_DEVICE,
		.instance_size = sizeof(TPUState),
		.instance_init = tpu_instance_init,
		.class_init = tpu_class_init,
		.interfaces = interfaces,
	};

	type_register_static(&tpu_info);
}
type_init(tpu_register_types)
