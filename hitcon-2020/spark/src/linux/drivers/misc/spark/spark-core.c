/*
 * Core functions for SPARK.
 *
 * Copyright (c) 2020 david942j
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <uapi/linux/spark.h>

#include "spark-internal.h"

struct spark_graph {
  size_t total;
  size_t capacity;
  struct spark_node **nodes;
};

struct spark_node_link {
  struct list_head head;
  struct spark_node *node;
  unsigned long long weight;
};

#define MAX_NUM_NEIGHBOR 256
static atomic_t cur_count = ATOMIC_INIT(0);

static void free_graph(struct spark_graph *graph)
{
  int i;

  for (i = 1; i < graph->total; i++)
    spark_node_put(graph->nodes[i]);
  kfree(graph->nodes);
}

void spark_node_get(struct spark_node *node)
{
  refcount_inc(&node->refcount);
}

void spark_node_put(struct spark_node *node)
{
  if (refcount_dec_and_test(&node->refcount)) {
    struct spark_node_link *link, *tmp;

    /* debug("release node %d", node->id); */
    if (node->graph) {
      /* debug("releasing node %d's graph", node->id); */
      free_graph(node->graph);
    }
    /* debug("releasing node %d's %d neighbors", node->id, node->nnb); */
    list_for_each_entry_safe (link, tmp, &node->nb, head)
      kfree(link);
    kfree(node);
  }
}

static void spark_node_push(struct spark_node *node, struct spark_node *other, unsigned int w)
{
  struct spark_node_link *lk = kzalloc(sizeof(*lk), GFP_KERNEL);

  if (!lk)
    return;
  /* debug("link (bytes=0x%lx) @ 0x%llx", sizeof(*lk), (unsigned long long)lk); */
  INIT_LIST_HEAD(&lk->head);
  lk->node = other;
  lk->weight = w;
  mutex_lock(&node->nb_lock);
  if (node->nnb >= MAX_NUM_NEIGHBOR)
    goto err;

  list_add(&lk->head, &node->nb);
  node->nnb++;
  mutex_unlock(&node->nb_lock);
  return;
err:
  mutex_unlock(&node->nb_lock);
  kfree(lk);
}

struct spark_node *spark_node_alloc(void)
{
  struct spark_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
 
  if (!node)
    return ERR_PTR(-ENOMEM);
  /* debug("node (bytes=0x%lx) @ 0x%llx", sizeof(*node), (unsigned long long)node); */
  node->id = atomic_inc_return(&cur_count) - 1;
  /* spark_node_get() */
  refcount_set(&node->refcount, 1);
  mutex_init(&node->state_lock);
  node->state = SPARK_NODE_STATE_WAITING;
  mutex_init(&node->nb_lock);
  INIT_LIST_HEAD(&node->nb);
  return node;
}

void spark_node_free(struct spark_node *node)
{
  spark_node_put(node);
}

int spark_node_link(struct spark_node *node, struct spark_node *other, unsigned int w)
{
  int ret = -EINVAL;

  if (node->id >= other->id)
    return -EINVAL;
  mutex_lock(&other->state_lock);
  mutex_lock(&node->state_lock);
  if (node->state == SPARK_NODE_STATE_WAITING &&
      other->state == SPARK_NODE_STATE_WAITING) {
    spark_node_push(node, other, w);
    spark_node_push(other, node, w);
    ret = 0;
  }
  mutex_unlock(&node->state_lock);
  mutex_unlock(&other->state_lock);
  return ret;
}

static void traversal(struct spark_node *node, struct spark_graph *graph) {
  struct spark_node_link *link;

  graph->nodes[graph->total] = node;
  if (graph->total != 0)
    spark_node_get(node);
  node->idx = graph->total++;
  if (graph->total == graph->capacity) {
    graph->capacity <<= 1;
    graph->nodes = krealloc(graph->nodes, graph->capacity * sizeof(*graph->nodes), GFP_KERNEL);
  }
  /* finalized node's nb won't be modified - safe to not hold the lock here */
  list_for_each_entry (link, &node->nb, head) {
    bool go = false;
    struct spark_node *y = link->node;
    /* bug: it's possible that y is freed here */

    mutex_lock(&y->state_lock);
    if (y->state == SPARK_NODE_STATE_WAITING) {
      go = true;
      y->state = SPARK_NODE_STATE_FINALIZED;
    }
    mutex_unlock(&y->state_lock);
    if (go)
      traversal(y, graph);
  }
}

int spark_node_finalize(struct spark_node *node)
{
  struct spark_graph *graph = kzalloc(sizeof(*graph), GFP_KERNEL);

  if (!graph)
    return -ENOMEM;
  /* debug("graph (bytes=0x%lx) @ 0x%llx", sizeof(*graph), (unsigned long long)graph); */
  mutex_lock(&node->state_lock);
  if (node->state != SPARK_NODE_STATE_WAITING) {
    kfree(graph);
    mutex_unlock(&node->state_lock);
    return -EINVAL;
  }
  node->state = SPARK_NODE_STATE_FINALIZED;
  mutex_unlock(&node->state_lock);

  graph->capacity = 2;
  graph->nodes = kmalloc_array(graph->capacity, sizeof(*graph->nodes), GFP_KERNEL);
  traversal(node, graph);
  /* debug("graph nodes (bytes=0x%lx) @ 0x%llx", sizeof(*graph->nodes) * graph->capacity, (unsigned long long)graph->nodes); */
  /* if (graph->total == 10) */
  /*   node->graph = 0x1337000; */
  /* else */
    node->graph = graph;
  return 0;
}

void spark_node_get_info(struct spark_node *node, struct spark_ioctl_info *info)
{
  mutex_lock(&node->nb_lock);
  info->nnb = node->nnb;
  mutex_unlock(&node->nb_lock);

  mutex_lock(&node->state_lock);
  if (node->state == SPARK_NODE_STATE_FINALIZED) {
    info->idx = node->idx;
    if (node->graph)
      info->graph_size = node->graph->total;
  }
  mutex_unlock(&node->state_lock);
}

static long long dijkstra(const struct spark_graph *graph, size_t st_idx, size_t ed_idx, unsigned long long *dis)
{
#define INF 0x7fffffffffffffffull
#define USED ~0ull
  const size_t n = graph->total;
  size_t now;
  int i;

  for (i = 0; i < n; i++)
    dis[i] = INF;
  dis[st_idx] = 0;
  now = st_idx;
  debug("%s: st=%lu ed=%lu", __func__, st_idx, ed_idx);
  while (now != ed_idx) {
    struct spark_node_link *link;
    struct spark_node *x = graph->nodes[now];
    unsigned long long next_min;
    const unsigned long long d = dis[now];

    if (d == USED || d == INF)/* should never happen */
      return 0;
    dis[now] = USED;
    list_for_each_entry (link, &x->nb, head) {
      struct spark_node *y = link->node;

      /* debug("now=%d nowd = 0x%llx idx=%d dis = 0x%llx", now, d, y->idx, d + link->weight); */
      if (dis[y->idx] != USED && dis[y->idx] > d + link->weight)
        dis[y->idx] = d + link->weight;
    }
    next_min = INF; now = st_idx; /* just in case */
    for (i = 0; i < n; i++)
      if (dis[i] != USED && dis[i] < next_min) {
        next_min = dis[i]; now = i;
      }
  }

  return dis[ed_idx];
}

long long spark_graph_query(struct spark_graph *graph, size_t a, size_t b) {
  unsigned long long *dis;
  long long ans;

  if (a >= graph->total || b >= graph->total)
    return 0;
  dis = kmalloc(sizeof(*dis) * graph->total, GFP_KERNEL);
  if (!dis)
    return -ENOMEM;
  debug("dis (bytes=0x%lx) @ 0x%llx", sizeof(*dis) * graph->total, (unsigned long long)dis);
  ans = dijkstra(graph, a, b, dis);
  kfree(dis);
  if (ans < 0)
    return 0;
  return ans;
}
