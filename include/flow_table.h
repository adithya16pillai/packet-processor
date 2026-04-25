/* Open-addressing hash table for 5-tuple flow tracking. */
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "common.h"

typedef struct {
    flow_entry_t *entries;
    size_t        capacity;
    size_t        mask;
    size_t        count;
    uint64_t      drops;
    uint64_t      collisions;
} flow_table_t;

flow_table_t *flow_table_create(size_t capacity);
void          flow_table_destroy(flow_table_t *ft);
int           flow_table_update(flow_table_t *ft, const flow_key_t *key, uint32_t bytes);
void          flow_table_iterate(const flow_table_t *ft,
                                 void (*cb)(const flow_entry_t *, void *), void *ctx);
uint32_t      flow_key_hash(const flow_key_t *key);
int           flow_key_equal(const flow_key_t *a, const flow_key_t *b);

#endif
