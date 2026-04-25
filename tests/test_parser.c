/* Unit tests for parse_packet. */
#include <string.h>
#include <arpa/inet.h>
#include "test_framework.h"
#include "parser.h"
#include "common.h"

static size_t build_tcp_frame(uint8_t *buf, size_t cap,
                              uint32_t src_ip_h, uint32_t dst_ip_h,
                              uint16_t src_port_h, uint16_t dst_port_h,
                              uint8_t flag_byte) {
    if (cap < 14 + 20 + 20) return 0;
    memset(buf, 0, 14 + 20 + 20);

    buf[12] = 0x08;
    buf[13] = 0x00;

    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    ip[1] = 0x00;
    uint16_t totlen = htons(40); memcpy(ip + 2, &totlen, 2);
    ip[8] = 64;
    ip[9] = 6;
    uint32_t s = htonl(src_ip_h); memcpy(ip + 12, &s, 4);
    uint32_t d = htonl(dst_ip_h); memcpy(ip + 16, &d, 4);

    uint8_t *tcp = buf + 14 + 20;
    uint16_t sp = htons(src_port_h); memcpy(tcp + 0, &sp, 2);
    uint16_t dp = htons(dst_port_h); memcpy(tcp + 2, &dp, 2);
    tcp[12] = 0x50;
    tcp[13] = flag_byte;

    return 14 + 20 + 20;
}

static size_t build_udp_frame(uint8_t *buf, size_t cap,
                              uint16_t src_port_h, uint16_t dst_port_h) {
    if (cap < 14 + 20 + 8) return 0;
    memset(buf, 0, 14 + 20 + 8);
    buf[12] = 0x08; buf[13] = 0x00;

    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    uint16_t totlen = htons(28); memcpy(ip + 2, &totlen, 2);
    ip[8] = 64;
    ip[9] = 17;

    uint8_t *udp = buf + 14 + 20;
    uint16_t sp = htons(src_port_h); memcpy(udp + 0, &sp, 2);
    uint16_t dp = htons(dst_port_h); memcpy(udp + 2, &dp, 2);
    return 14 + 20 + 8;
}

TEST(parse_tcp_happy_path) {
    uint8_t buf[64];
    size_t n = build_tcp_frame(buf, sizeof(buf),
                               0x0A000001, 0xC0A80101,
                               54321, 443, 0x12);
    ASSERT(n > 0);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    ASSERT_EQ_INT(parse_packet(buf, n, &pkt), 0);

    ASSERT_EQ_U32(pkt.ethertype, 0x0800);
    ASSERT_EQ_INT(pkt.has_ip, 1);
    ASSERT_EQ_INT(pkt.has_transport, 1);
    ASSERT_EQ_U32(pkt.src_ip, 0x0A000001);
    ASSERT_EQ_U32(pkt.dst_ip, 0xC0A80101);
    ASSERT_EQ_INT(pkt.src_port, 54321);
    ASSERT_EQ_INT(pkt.dst_port, 443);
    ASSERT_EQ_INT(pkt.protocol, 6);
    ASSERT_EQ_INT(pkt.ttl, 64);
    ASSERT((pkt.tcp_flags & TCP_FLAG_SYN) != 0);
    ASSERT((pkt.tcp_flags & TCP_FLAG_ACK) != 0);
    ASSERT((pkt.tcp_flags & TCP_FLAG_FIN) == 0);
}

TEST(parse_udp_happy_path) {
    uint8_t buf[64];
    size_t n = build_udp_frame(buf, sizeof(buf), 53, 5353);
    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    ASSERT_EQ_INT(parse_packet(buf, n, &pkt), 0);
    ASSERT_EQ_INT(pkt.protocol, 17);
    ASSERT_EQ_INT(pkt.src_port, 53);
    ASSERT_EQ_INT(pkt.dst_port, 5353);
}

TEST(truncated_ethernet) {
    uint8_t buf[8] = {0};
    parsed_packet_t pkt;
    ASSERT_EQ_INT(parse_packet(buf, 8, &pkt), -1);
}

TEST(truncated_ip_header) {
    uint8_t buf[18] = {0};
    buf[12] = 0x08; buf[13] = 0x00;
    parsed_packet_t pkt;
    ASSERT_EQ_INT(parse_packet(buf, 18, &pkt), -1);
}

TEST(truncated_tcp) {
    uint8_t buf[14 + 20 + 4] = {0};
    buf[12] = 0x08; buf[13] = 0x00;
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    ip[9] = 6;
    parsed_packet_t pkt;
    ASSERT_EQ_INT(parse_packet(buf, sizeof(buf), &pkt), -1);
}

TEST(non_ipv4_ethertype_is_soft) {
    uint8_t buf[14] = {0};
    buf[12] = 0x86; buf[13] = 0xDD;
    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    ASSERT_EQ_INT(parse_packet(buf, sizeof(buf), &pkt), 0);
    ASSERT_EQ_INT(pkt.has_ip, 0);
    ASSERT_EQ_U32(pkt.ethertype, 0x86DD);
}

TEST(bad_ip_version_is_rejected) {
    uint8_t buf[14 + 20];
    memset(buf, 0, sizeof(buf));
    buf[12] = 0x08; buf[13] = 0x00;
    buf[14] = 0x65;
    parsed_packet_t pkt;
    ASSERT_EQ_INT(parse_packet(buf, sizeof(buf), &pkt), -1);
}

TEST(fragment_does_not_parse_transport) {
    uint8_t buf[14 + 20 + 20];
    memset(buf, 0, sizeof(buf));
    buf[12] = 0x08; buf[13] = 0x00;
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    ip[9] = 6;
    uint16_t frag = htons(0x0001);
    memcpy(ip + 6, &frag, 2);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    ASSERT_EQ_INT(parse_packet(buf, sizeof(buf), &pkt), 0);
    ASSERT_EQ_INT(pkt.has_ip, 1);
    ASSERT_EQ_INT(pkt.has_transport, 0);
}

int main(void) {
    printf("== test_parser ==\n");
    RUN(parse_tcp_happy_path);
    RUN(parse_udp_happy_path);
    RUN(truncated_ethernet);
    RUN(truncated_ip_header);
    RUN(truncated_tcp);
    RUN(non_ipv4_ethertype_is_soft);
    RUN(bad_ip_version_is_rejected);
    RUN(fragment_does_not_parse_transport);
    return test_finish();
}
