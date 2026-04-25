/* Flow statistics output formatters. */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "stats.h"

static const char *proto_name(uint8_t p) {
    switch (p) {
    case 1:   return "ICMP";
    case 6:   return "TCP";
    case 17:  return "UDP";
    case 47:  return "GRE";
    case 50:  return "ESP";
    case 132: return "SCTP";
    default:  return "?";
    }
}

static void ip_to_str(uint32_t host_order_ip, char *buf, size_t buflen) {
    uint32_t net = htonl(host_order_ip);
    inet_ntop(AF_INET, &net, buf, (socklen_t)buflen);
}

static double duration_sec(const struct timespec *first, const struct timespec *last) {
    double a = (double)first->tv_sec + first->tv_nsec / 1e9;
    double b = (double)last->tv_sec  + last->tv_nsec  / 1e9;
    double d = b - a;
    return d < 0 ? 0 : d;
}

struct table_ctx {
    FILE  *out;
    size_t row;
};

static void table_row_cb(const flow_entry_t *e, void *vctx) {
    struct table_ctx *c = vctx;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(e->key.src_ip, src, sizeof(src));
    ip_to_str(e->key.dst_ip, dst, sizeof(dst));
    fprintf(c->out,
            "  %-15s %5u  ->  %-15s %5u  %-5s  %10" PRIu64 "  %14" PRIu64 "  %9.2fs\n",
            src, e->key.src_port,
            dst, e->key.dst_port,
            proto_name(e->key.protocol),
            e->packet_count,
            e->byte_count,
            duration_sec(&e->first_seen, &e->last_seen));
    c->row++;
}

void stats_print_flows(const flow_table_t *ft, FILE *out) {
    if (!out) out = stdout;
    fprintf(out, "  %-15s %5s      %-15s %5s  %-5s  %10s  %14s  %9s\n",
            "SRC IP", "SPORT", "DST IP", "DPORT", "PROTO", "PACKETS", "BYTES", "DURATION");
    fprintf(out, "  %.*s\n", 96, "------------------------------------------------------------------------------------------------");
    struct table_ctx ctx = { .out = out, .row = 0 };
    flow_table_iterate(ft, table_row_cb, &ctx);
    if (ctx.row == 0) {
        fprintf(out, "  (no flows recorded)\n");
    }
}

struct json_ctx {
    FILE *out;
    int   first;
};

static void json_row_cb(const flow_entry_t *e, void *vctx) {
    struct json_ctx *c = vctx;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(e->key.src_ip, src, sizeof(src));
    ip_to_str(e->key.dst_ip, dst, sizeof(dst));
    if (!c->first) fputs(",\n", c->out);
    c->first = 0;
    fprintf(c->out,
            "    {\"src_ip\":\"%s\",\"src_port\":%u,"
            "\"dst_ip\":\"%s\",\"dst_port\":%u,"
            "\"protocol\":%u,"
            "\"packets\":%" PRIu64 ",\"bytes\":%" PRIu64 ","
            "\"first_seen\":%ld.%09ld,\"last_seen\":%ld.%09ld}",
            src, e->key.src_port,
            dst, e->key.dst_port,
            e->key.protocol,
            e->packet_count, e->byte_count,
            (long)e->first_seen.tv_sec, e->first_seen.tv_nsec,
            (long)e->last_seen.tv_sec,  e->last_seen.tv_nsec);
}

void stats_print_flows_json(const flow_table_t *ft, FILE *out) {
    if (!out) out = stdout;
    fputs("{\n  \"flows\": [\n", out);
    struct json_ctx ctx = { .out = out, .first = 1 };
    flow_table_iterate(ft, json_row_cb, &ctx);
    fputs("\n  ]\n}\n", out);
}

void stats_print_summary(FILE *out,
                         uint64_t total_packets,
                         uint64_t matched_packets,
                         const flow_table_t *ft) {
    if (!out) out = stdout;
    fprintf(out, "Total packets:    %" PRIu64 "\n", total_packets);
    fprintf(out, "Matched packets:  %" PRIu64 "\n", matched_packets);
    if (ft) {
        fprintf(out, "Active flows:     %zu\n",     ft->count);
        fprintf(out, "Flow drops:       %" PRIu64 " (table full)\n", ft->drops);
        double avg_probes = ft->count ? (double)ft->collisions / (double)ft->count : 0.0;
        fprintf(out, "Avg probe dist:   %.2f\n", avg_probes);
    }
}
