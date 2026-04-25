/* Entry point: argument parsing, signal handling, capture loop. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>

#include "common.h"
#include "capture.h"
#include "parser.h"
#include "filter.h"
#include "flow_table.h"
#include "stats.h"
#include "pcap_writer.h"

static volatile sig_atomic_t g_running  = 1;
static volatile sig_atomic_t g_dump_now = 0;

static void on_sigint(int sig)  { (void)sig; g_running  = 0; }
static void on_sigusr1(int sig) { (void)sig; g_dump_now = 1; }

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -i <interface> [OPTIONS]\n"
        "\n"
        "Required:\n"
        "  -i <iface>     Network interface (e.g. eth0, wlan0)\n"
        "\n"
        "Options:\n"
        "  -f <rule>      Filter rule (repeatable, AND semantics)\n"
        "                   src_ip=10.0.0.0/8    dst_ip=192.168.1.1\n"
        "                   src_port=443         dst_port=80\n"
        "                   proto=tcp | udp | icmp | <0..255>\n"
        "  -w <file.pcap> Write matched packets to a libpcap file\n"
        "  -j             Emit JSON stats on exit (instead of ASCII table)\n"
        "  -p             Enable promiscuous mode on the interface\n"
        "  -t <sec>       Print stats every <sec> seconds (0 = only on exit)\n"
        "  -c <count>     Stop after processing <count> matched packets\n"
        "  -h             This help\n"
        "\n"
        "Signals:\n"
        "  SIGINT (Ctrl+C) — flush stats and exit\n"
        "  SIGUSR1         — dump stats without exiting\n"
        "\n"
        "Example:\n"
        "  sudo %s -i eth0 -f proto=tcp -f dst_port=443 -w https.pcap\n",
        prog, prog);
}

static double ts_diff_sec(const struct timespec *a, const struct timespec *b) {
    return (double)(b->tv_sec - a->tv_sec) + (b->tv_nsec - a->tv_nsec) / 1e9;
}

int main(int argc, char *argv[]) {
    const char   *interface    = NULL;
    const char   *pcap_path    = NULL;
    filter_rule_t filters[MAX_FILTERS];
    int           filter_count = 0;
    int           json_output  = 0;
    int           promisc      = 0;
    int           interval_sec = 0;
    uint64_t      max_matched  = 0;

    int opt;
    while ((opt = getopt(argc, argv, "i:f:w:jpt:c:h")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'f':
            if (filter_count >= MAX_FILTERS) {
                fprintf(stderr, "Too many filters (max %d)\n", MAX_FILTERS);
                return 1;
            }
            if (filter_parse(optarg, &filters[filter_count]) != 0) {
                fprintf(stderr, "Invalid filter: %s\n", optarg);
                return 1;
            }
            filter_count++;
            break;
        case 'w':
            pcap_path = optarg;
            break;
        case 'j':
            json_output = 1;
            break;
        case 'p':
            promisc = 1;
            break;
        case 't': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v < 0) {
                fprintf(stderr, "Invalid interval: %s\n", optarg);
                return 1;
            }
            interval_sec = (int)v;
            break;
        }
        case 'c': {
            char *end = NULL;
            long long v = strtoll(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v < 0) {
                fprintf(stderr, "Invalid count: %s\n", optarg);
                return 1;
            }
            max_matched = (uint64_t)v;
            break;
        }
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!interface) {
        fprintf(stderr, "Missing required -i <interface>\n\n");
        print_usage(argv[0]);
        return 1;
    }

    struct sigaction sa_int = { .sa_handler = on_sigint };
    sigemptyset(&sa_int.sa_mask);
    sigaction(SIGINT,  &sa_int, NULL);
    sigaction(SIGTERM, &sa_int, NULL);

    struct sigaction sa_usr = { .sa_handler = on_sigusr1 };
    sigemptyset(&sa_usr.sa_mask);
    sigaction(SIGUSR1, &sa_usr, NULL);

    int sockfd = capture_open(interface);
    if (sockfd < 0) {
        fprintf(stderr,
                "Failed to open capture on %s — needs root or CAP_NET_RAW.\n"
                "Hint: sudo %s ...  or  sudo setcap cap_net_raw,cap_net_admin=eip ./pktproc\n",
                interface, argv[0]);
        return 1;
    }

    if (promisc && capture_set_promisc(sockfd, interface, 1) != 0) {
        fprintf(stderr, "Warning: failed to enable promiscuous mode\n");
    }

    flow_table_t *ft = flow_table_create(FLOW_TABLE_SIZE);
    if (!ft) {
        fprintf(stderr, "Failed to allocate flow table\n");
        capture_close(sockfd);
        return 1;
    }

    pcap_writer_t *pcap_w = NULL;
    if (pcap_path) {
        pcap_w = pcap_writer_open(pcap_path);
        if (!pcap_w) {
            perror("pcap_writer_open");
            flow_table_destroy(ft);
            capture_close(sockfd);
            return 1;
        }
    }

    fprintf(stderr, "pktproc: capturing on %s (%d filters, pcap=%s)\n",
            interface, filter_count, pcap_path ? pcap_path : "off");
    for (int i = 0; i < filter_count; i++) {
        char buf[64];
        filter_describe(&filters[i], buf, sizeof(buf));
        fprintf(stderr, "  filter[%d]: %s\n", i, buf);
    }
    fprintf(stderr, "Ctrl+C to stop.\n\n");

    uint8_t buf[MAX_PACKET_SIZE];
    parsed_packet_t pkt;
    uint64_t total_packets   = 0;
    uint64_t matched_packets = 0;

    struct timespec start_ts, last_dump_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    last_dump_ts = start_ts;

    while (g_running) {
        ssize_t len = capture_next(sockfd, buf, sizeof(buf));

        if (len < 0) {
            if (errno == EINTR) continue;
            perror("capture_next");
            break;
        }

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        if (len > 0) {
            total_packets++;

            memset(&pkt, 0, sizeof(pkt));
            pkt.capture_len = (uint32_t)len;
            clock_gettime(CLOCK_REALTIME, &pkt.timestamp);

            if (parse_packet(buf, (size_t)len, &pkt) != 0) continue;
            if (!filter_match(&pkt, filters, filter_count)) continue;

            matched_packets++;

            if (pkt.has_ip) {
                flow_key_t key = {
                    .src_ip   = pkt.src_ip,
                    .dst_ip   = pkt.dst_ip,
                    .src_port = pkt.src_port,
                    .dst_port = pkt.dst_port,
                    .protocol = pkt.protocol,
                };
                flow_table_update(ft, &key, pkt.capture_len);
            }

            if (pcap_w) {
                pcap_writer_append(pcap_w, &pkt.timestamp, buf, (size_t)len);
            }

            if (max_matched && matched_packets >= max_matched) {
                g_running = 0;
            }
        }

        if (interval_sec > 0 && ts_diff_sec(&last_dump_ts, &now) >= (double)interval_sec) {
            fprintf(stderr, "\n--- interval dump ---\n");
            stats_print_summary(stderr, total_packets, matched_packets, ft);
            last_dump_ts = now;
        }

        if (g_dump_now) {
            g_dump_now = 0;
            fprintf(stderr, "\n--- SIGUSR1 dump ---\n");
            stats_print_summary(stderr, total_packets, matched_packets, ft);
            stats_print_flows(ft, stderr);
        }
    }

    struct timespec end_ts;
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    double elapsed = ts_diff_sec(&start_ts, &end_ts);

    fprintf(stderr, "\n--- Capture Statistics ---\n");
    stats_print_summary(stderr, total_packets, matched_packets, ft);
    fprintf(stderr, "Elapsed:          %.2fs\n", elapsed);
    if (elapsed > 0) {
        fprintf(stderr, "Throughput:       %.0f pps\n", total_packets / elapsed);
    }
    fputc('\n', stderr);

    if (json_output) {
        stats_print_flows_json(ft, stdout);
    } else {
        stats_print_flows(ft, stdout);
    }

    if (pcap_w) {
        fprintf(stderr, "\nWrote %" PRIu64 " bytes to %s\n",
                pcap_writer_bytes(pcap_w), pcap_path);
        pcap_writer_close(pcap_w);
    }

    flow_table_destroy(ft);
    capture_close(sockfd);
    return 0;
}
