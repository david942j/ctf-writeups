/*
 * Internal common interfaces for SPARK.
 *
 * Copyright (c) 2020 david942j
 */
#ifndef _SPARK_INTERNAL_H
#define _SPARK_INTERNAL_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>

// #define DAVID942J

#ifdef DAVID942J
 #define debug(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
 #define debug(...)
#endif /* DAVID942j */

enum spark_node_state {
  SPARK_NODE_STATE_WAITING,
  SPARK_NODE_STATE_FINALIZED,
};

struct spark_graph;

/* structure bound to every node */
struct spark_node {
  size_t id;
  refcount_t refcount;
  struct mutex state_lock;
  enum spark_node_state state;
  struct mutex nb_lock;
  size_t nnb;
  struct list_head nb;
  size_t idx; /* set when finalizing */
  struct spark_graph *graph; /* only used by the graph leader */
};

/* functions implemented in spark-core.c */

struct spark_node *spark_node_alloc(void);
void spark_node_free(struct spark_node *node);
void spark_node_get(struct spark_node *node);
void spark_node_put(struct spark_node *node);
void spark_node_get_info(struct spark_node *node, struct spark_ioctl_info *info);

/* graph operations */

int spark_node_link(struct spark_node *node, struct spark_node *other, unsigned int w);
int spark_node_finalize(struct spark_node *node);
long long spark_graph_query(struct spark_graph *graph, size_t a, size_t b);

#endif /* _SPARK_INTERNAL_H */
