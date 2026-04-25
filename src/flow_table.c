/* FNV-1a hashed open-addressing flow table. */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "flow_table.h"

#define FNV_OFFSET 2166136261u
#define FNV_PRIME  16777619u

uint32_t flow_key_hash(const flow_key_t *key) {
    uint32_t h = FNV_OFFSET;
    const uint8_t *p = (const uint8_t *)key;
    for (size_t i = 0; i < sizeof(*key); i++) {
        h ^= p[i];
        h *= FNV_PRIME;
    }
    return h;
}

int flow_key_equal(const flow_key_t *a, const flow_key_t *b) {
    return memcmp(a, b, sizeof(*a)) == 0;
}

static int is_power_of_two(size_t x) {
    return x != 0 && (x & (x - 1)) == 0;
}

flow_table_t *flow_table_create(size_t capacity) {
    if (!is_power_of_two(capacity)) return NULL;

    flow_table_t *ft = calloc(1, sizeof(*ft));
    if (!ft) return NULL;

    ft->entries = calloc(capacity, sizeof(flow_entry_t));
    if (!ft->entries) { free(ft); return NULL; }

    ft->capacity = capacity;
    ft->mask     = capacity - 1;
    return ft;
}

void flow_table_destroy(flow_table_t *ft) {
    if (!ft) return;
    free(ft->entries);
    free(ft);
}

int flow_table_update(flow_table_t *ft, const flow_key_t *key, uint32_t bytes) {
    if (!ft || !key) return -1;

    uint32_t h = flow_key_hash(key);
    size_t idx = h & ft->mask;

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    for (size_t probe = 0; probe < MAX_PROBE_DIST; probe++) {
        flow_entry_t *e = &ft->entries[idx];

        if (!e->active) {
            e->active       = 1;
            e->key          = *key;
            e->packet_count = 1;
            e->byte_count   = bytes;
            e->first_seen   = now;
            e->last_seen    = now;
            ft->count++;
            ft->collisions += probe;
            return 1;
        }

        if (flow_key_equal(&e->key, key)) {
            e->packet_count++;
            e->byte_count += bytes;
            e->last_seen = now;
            ft->collisions += probe;
            return 0;
        }

        idx = (idx + 1) & ft->mask;
    }

    ft->drops++;
    return -1;
}

void flow_table_iterate(const flow_table_t *ft,
                        void (*cb)(const flow_entry_t *, void *), void *ctx) {
    if (!ft || !cb) return;
    for (size_t i = 0; i < ft->capacity; i++) {
        const flow_entry_t *e = &ft->entries[i];
        if (e->active) cb(e, ctx);
    }
}
