/* Unit tests for flow_table operations. */
#include <string.h>
#include "test_framework.h"
#include "flow_table.h"

static flow_key_t mk_key(uint32_t s, uint32_t d, uint16_t sp, uint16_t dp, uint8_t pr) {
    flow_key_t k = {0};
    k.src_ip = s; k.dst_ip = d; k.src_port = sp; k.dst_port = dp; k.protocol = pr;
    return k;
}

TEST(create_and_destroy) {
    flow_table_t *ft = flow_table_create(16);
    ASSERT(ft != NULL);
    ASSERT_EQ_INT(ft->capacity, 16);
    ASSERT_EQ_INT(ft->count, 0);
    flow_table_destroy(ft);
}

TEST(rejects_non_power_of_two_capacity) {
    ASSERT(flow_table_create(15) == NULL);
    ASSERT(flow_table_create(0)  == NULL);
}

TEST(insert_then_update) {
    flow_table_t *ft = flow_table_create(64);
    flow_key_t k = mk_key(1, 2, 80, 443, 6);

    ASSERT_EQ_INT(flow_table_update(ft, &k, 100), 1);
    ASSERT_EQ_INT(ft->count, 1);

    ASSERT_EQ_INT(flow_table_update(ft, &k, 200), 0);
    ASSERT_EQ_INT(ft->count, 1);

    flow_table_destroy(ft);
}

TEST(distinct_keys_are_separate) {
    flow_table_t *ft = flow_table_create(64);
    flow_key_t a = mk_key(1, 2, 80, 443, 6);
    flow_key_t b = mk_key(2, 1, 443, 80, 6);

    flow_table_update(ft, &a, 100);
    flow_table_update(ft, &b, 200);
    ASSERT_EQ_INT(ft->count, 2);
    flow_table_destroy(ft);
}

TEST(hash_is_deterministic_and_key_sensitive) {
    flow_key_t a = mk_key(1, 2, 80, 443, 6);
    flow_key_t b = mk_key(1, 2, 80, 443, 6);
    flow_key_t c = mk_key(1, 2, 80, 443, 17);
    ASSERT_EQ_U32(flow_key_hash(&a), flow_key_hash(&b));
    ASSERT(flow_key_hash(&a) != flow_key_hash(&c));
}

struct count_ctx { int n; uint64_t packets; uint64_t bytes; };

static void count_cb(const flow_entry_t *e, void *v) {
    struct count_ctx *c = v;
    c->n++;
    c->packets += e->packet_count;
    c->bytes   += e->byte_count;
}

TEST(iterate_visits_all_active) {
    flow_table_t *ft = flow_table_create(64);
    for (uint32_t i = 0; i < 10; i++) {
        flow_key_t k = mk_key(i, i + 1, 1000, 2000, 6);
        flow_table_update(ft, &k, 50);
    }
    struct count_ctx c = {0};
    flow_table_iterate(ft, count_cb, &c);
    ASSERT_EQ_INT(c.n, 10);
    ASSERT_EQ_INT(c.packets, 10);
    ASSERT_EQ_INT(c.bytes, 500);
    flow_table_destroy(ft);
}

TEST(full_table_drops_new_flows) {
    flow_table_t *ft = flow_table_create(4);
    int inserted = 0;
    for (uint32_t i = 0; i < 64; i++) {
        flow_key_t k = mk_key(i, i + 1, 1000, 2000, 6);
        if (flow_table_update(ft, &k, 10) == 1) inserted++;
    }
    ASSERT(inserted <= 4);
    ASSERT(ft->drops > 0);
    flow_table_destroy(ft);
}

int main(void) {
    printf("== test_flow_table ==\n");
    RUN(create_and_destroy);
    RUN(rejects_non_power_of_two_capacity);
    RUN(insert_then_update);
    RUN(distinct_keys_are_separate);
    RUN(hash_is_deterministic_and_key_sensitive);
    RUN(iterate_visits_all_active);
    RUN(full_table_drops_new_flows);
    return test_finish();
}
