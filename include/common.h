/* Shared types: 5-tuple flow key, parsed packet, filter rule. */
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define MAX_PACKET_SIZE   65535
#define FLOW_TABLE_SIZE   65536
#define MAX_FILTERS       32
#define MAX_PROBE_DIST    64

#if defined(__GNUC__) || defined(__clang__)
#  define LIKELY(x)   __builtin_expect(!!(x), 1)
#  define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define LIKELY(x)   (x)
#  define UNLIKELY(x) (x)
#endif

typedef struct __attribute__((packed)) {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} flow_key_t;

typedef struct {
    flow_key_t      key;
    uint64_t        packet_count;
    uint64_t        byte_count;
    struct timespec first_seen;
    struct timespec last_seen;
    int             active;
} flow_entry_t;

typedef struct {
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint16_t ethertype;

    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  protocol;
    uint8_t  ttl;
    uint16_t ip_total_len;
    uint8_t  ip_version;

    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;

    uint8_t  icmp_type;
    uint8_t  icmp_code;

    uint32_t        capture_len;
    struct timespec timestamp;
    int             has_ip;
    int             has_transport;
} parsed_packet_t;

#define TCP_FLAG_FIN  (1u << 0)
#define TCP_FLAG_SYN  (1u << 1)
#define TCP_FLAG_RST  (1u << 2)
#define TCP_FLAG_PSH  (1u << 3)
#define TCP_FLAG_ACK  (1u << 4)
#define TCP_FLAG_URG  (1u << 5)

typedef enum {
    FILTER_SRC_IP,
    FILTER_DST_IP,
    FILTER_SRC_PORT,
    FILTER_DST_PORT,
    FILTER_PROTOCOL
} filter_field_t;

typedef struct {
    filter_field_t field;
    uint32_t       value;
    uint32_t       mask;
} filter_rule_t;

#endif
