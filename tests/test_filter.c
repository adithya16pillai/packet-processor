/* Unit tests for filter parsing and matching. */
#include <string.h>
#include "test_framework.h"
#include "filter.h"

static parsed_packet_t make_pkt(uint32_t src, uint32_t dst,
                                uint16_t sport, uint16_t dport,
                                uint8_t proto) {
    parsed_packet_t p;
    memset(&p, 0, sizeof(p));
    p.has_ip = 1;
    p.has_transport = 1;
    p.src_ip = src; p.dst_ip = dst;
    p.src_port = sport; p.dst_port = dport;
    p.protocol = proto;
    return p;
}

TEST(parse_ip_exact) {
    filter_rule_t r;
    ASSERT_EQ_INT(filter_parse("src_ip=10.0.0.1", &r), 0);
    ASSERT_EQ_INT(r.field, FILTER_SRC_IP);
    ASSERT_EQ_U32(r.value, 0x0A000001);
    ASSERT_EQ_U32(r.mask, 0xFFFFFFFF);
}

TEST(parse_ip_cidr_24) {
    filter_rule_t r;
    ASSERT_EQ_INT(filter_parse("dst_ip=192.168.1.0/24", &r), 0);
    ASSERT_EQ_INT(r.field, FILTER_DST_IP);
    ASSERT_EQ_U32(r.value, 0xC0A80100);
    ASSERT_EQ_U32(r.mask, 0xFFFFFF00);
}

TEST(parse_ip_cidr_8_canonicalizes) {
    filter_rule_t r;
    ASSERT_EQ_INT(filter_parse("src_ip=10.1.2.3/8", &r), 0);
    ASSERT_EQ_U32(r.value, 0x0A000000);
    ASSERT_EQ_U32(r.mask, 0xFF000000);
}

TEST(parse_ip_bad_prefix_rejected) {
    filter_rule_t r;
    ASSERT_EQ_INT(filter_parse("src_ip=10.0.0.1/33", &r), -1);
    ASSERT_EQ_INT(filter_parse("src_ip=10.0.0.1/-1", &r), -1);
    ASSERT_EQ_INT(filter_parse("src_ip=not.an.ip.addr", &r), -1);
}

TEST(parse_port_and_proto) {
    filter_rule_t r;
    ASSERT_EQ_INT(filter_parse("src_port=443", &r), 0);
    ASSERT_EQ_INT(r.field, FILTER_SRC_PORT);
    ASSERT_EQ_U32(r.value, 443);

    ASSERT_EQ_INT(filter_parse("proto=tcp", &r), 0);
    ASSERT_EQ_U32(r.value, 6);

    ASSERT_EQ_INT(filter_parse("proto=UDP", &r), 0);
    ASSERT_EQ_U32(r.value, 17);

    ASSERT_EQ_INT(filter_parse("protocol=1", &r), 0);
    ASSERT_EQ_U32(r.value, 1);
}

TEST(parse_rejects_garbage) {
    filter_rule_t r;
    ASSERT_EQ_INT(filter_parse("", &r), -1);
    ASSERT_EQ_INT(filter_parse("=5", &r), -1);
    ASSERT_EQ_INT(filter_parse("src_port=", &r), -1);
    ASSERT_EQ_INT(filter_parse("src_port=99999", &r), -1);
    ASSERT_EQ_INT(filter_parse("whatever=5", &r), -1);
}

TEST(match_exact_ip) {
    filter_rule_t r; filter_parse("dst_ip=8.8.8.8", &r);
    parsed_packet_t p = make_pkt(0, 0x08080808, 0, 53, 17);
    ASSERT_EQ_INT(filter_match(&p, &r, 1), 1);
    p.dst_ip = 0x08080404;
    ASSERT_EQ_INT(filter_match(&p, &r, 1), 0);
}

TEST(match_cidr_prefix) {
    filter_rule_t r; filter_parse("src_ip=10.0.0.0/8", &r);
    parsed_packet_t p = make_pkt(0x0A0B0C0D, 0, 0, 0, 6);
    ASSERT_EQ_INT(filter_match(&p, &r, 1), 1);
    p.src_ip = 0x0B010101;
    ASSERT_EQ_INT(filter_match(&p, &r, 1), 0);
}

TEST(match_multiple_rules_is_AND) {
    filter_rule_t rules[2];
    filter_parse("proto=tcp",     &rules[0]);
    filter_parse("dst_port=443",  &rules[1]);
    parsed_packet_t p = make_pkt(0, 0, 1234, 443, 6);
    ASSERT_EQ_INT(filter_match(&p, rules, 2), 1);

    p.dst_port = 80;
    ASSERT_EQ_INT(filter_match(&p, rules, 2), 0);

    p.dst_port = 443; p.protocol = 17;
    ASSERT_EQ_INT(filter_match(&p, rules, 2), 0);
}

TEST(match_with_zero_rules_always_true) {
    parsed_packet_t p = make_pkt(0, 0, 0, 0, 0);
    ASSERT_EQ_INT(filter_match(&p, NULL, 0), 1);
}

TEST(describe_roundtrip) {
    filter_rule_t r; filter_parse("dst_ip=192.168.1.0/24", &r);
    char buf[64];
    filter_describe(&r, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "dst_ip=192.168.1.0/24");
}

int main(void) {
    printf("== test_filter ==\n");
    RUN(parse_ip_exact);
    RUN(parse_ip_cidr_24);
    RUN(parse_ip_cidr_8_canonicalizes);
    RUN(parse_ip_bad_prefix_rejected);
    RUN(parse_port_and_proto);
    RUN(parse_rejects_garbage);
    RUN(match_exact_ip);
    RUN(match_cidr_prefix);
    RUN(match_multiple_rules_is_AND);
    RUN(match_with_zero_rules_always_true);
    RUN(describe_roundtrip);
    return test_finish();
}
