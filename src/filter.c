/* Filter rule parser and packet matcher. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>
#include <arpa/inet.h>

#include "filter.h"

static uint32_t prefix_to_mask(int bits) {
    if (bits <= 0)  return 0u;
    if (bits >= 32) return 0xFFFFFFFFu;
    return (uint32_t)(0xFFFFFFFFu << (32 - bits));
}

static int parse_ip_rule(const char *val, filter_rule_t *rule) {
    char buf[64];
    if (strlen(val) >= sizeof(buf)) return -1;
    strcpy(buf, val);

    int prefix = 32;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long p = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || p < 0 || p > 32) return -1;
        prefix = (int)p;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;

    rule->value = ntohl(addr.s_addr);
    rule->mask  = prefix_to_mask(prefix);
    rule->value &= rule->mask;
    return 0;
}

static int parse_port_rule(const char *val, filter_rule_t *rule) {
    char *end = NULL;
    long port = strtol(val, &end, 10);
    if (end == val || *end != '\0' || port < 0 || port > 65535) return -1;
    rule->value = (uint32_t)port;
    rule->mask  = 0xFFFFu;
    return 0;
}

static int parse_proto_rule(const char *val, filter_rule_t *rule) {
    long p = -1;
    if (strcasecmp(val, "tcp") == 0)       p = 6;
    else if (strcasecmp(val, "udp") == 0)  p = 17;
    else if (strcasecmp(val, "icmp") == 0) p = 1;
    else {
        char *end = NULL;
        p = strtol(val, &end, 10);
        if (end == val || *end != '\0' || p < 0 || p > 255) return -1;
    }
    rule->value = (uint32_t)p;
    rule->mask  = 0xFFu;
    return 0;
}

int filter_parse(const char *rule_str, filter_rule_t *rule) {
    if (!rule_str || !rule) return -1;

    while (*rule_str == ' ' || *rule_str == '\t') rule_str++;

    const char *eq = strchr(rule_str, '=');
    if (!eq || eq == rule_str) return -1;

    char field[32];
    size_t field_len = (size_t)(eq - rule_str);
    if (field_len == 0 || field_len >= sizeof(field)) return -1;
    memcpy(field, rule_str, field_len);
    field[field_len] = '\0';
    while (field_len > 0 && (field[field_len - 1] == ' ' || field[field_len - 1] == '\t')) {
        field[--field_len] = '\0';
    }

    const char *val = eq + 1;
    while (*val == ' ' || *val == '\t') val++;
    if (*val == '\0') return -1;

    memset(rule, 0, sizeof(*rule));

    if (strcmp(field, "src_ip") == 0) {
        rule->field = FILTER_SRC_IP;
        return parse_ip_rule(val, rule);
    } else if (strcmp(field, "dst_ip") == 0) {
        rule->field = FILTER_DST_IP;
        return parse_ip_rule(val, rule);
    } else if (strcmp(field, "src_port") == 0) {
        rule->field = FILTER_SRC_PORT;
        return parse_port_rule(val, rule);
    } else if (strcmp(field, "dst_port") == 0) {
        rule->field = FILTER_DST_PORT;
        return parse_port_rule(val, rule);
    } else if (strcmp(field, "proto") == 0 || strcmp(field, "protocol") == 0) {
        rule->field = FILTER_PROTOCOL;
        return parse_proto_rule(val, rule);
    }
    return -1;
}

static int match_one(const parsed_packet_t *pkt, const filter_rule_t *r) {
    switch (r->field) {
    case FILTER_SRC_IP:
        return pkt->has_ip && ((pkt->src_ip & r->mask) == r->value);
    case FILTER_DST_IP:
        return pkt->has_ip && ((pkt->dst_ip & r->mask) == r->value);
    case FILTER_SRC_PORT:
        return pkt->has_transport && pkt->src_port == (uint16_t)r->value;
    case FILTER_DST_PORT:
        return pkt->has_transport && pkt->dst_port == (uint16_t)r->value;
    case FILTER_PROTOCOL:
        return pkt->has_ip && pkt->protocol == (uint8_t)r->value;
    }
    return 0;
}

int filter_match(const parsed_packet_t *pkt, const filter_rule_t *rules, int count) {
    if (count <= 0) return 1;
    for (int i = 0; i < count; i++) {
        if (!match_one(pkt, &rules[i])) return 0;
    }
    return 1;
}

static int popcount_u32(uint32_t x) {
    int c = 0;
    while (x) { c++; x &= x - 1; }
    return c;
}

void filter_describe(const filter_rule_t *rule, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    out[0] = '\0';

    switch (rule->field) {
    case FILTER_SRC_IP:
    case FILTER_DST_IP: {
        uint32_t net = htonl(rule->value);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net, ip, sizeof(ip));
        int prefix = popcount_u32(rule->mask);
        snprintf(out, out_len, "%s=%s/%d",
                 rule->field == FILTER_SRC_IP ? "src_ip" : "dst_ip", ip, prefix);
        return;
    }
    case FILTER_SRC_PORT:
        snprintf(out, out_len, "src_port=%u", rule->value);
        return;
    case FILTER_DST_PORT:
        snprintf(out, out_len, "dst_port=%u", rule->value);
        return;
    case FILTER_PROTOCOL:
        snprintf(out, out_len, "proto=%u", rule->value);
        return;
    }
}
