/* Bounds-checked L2-L4 header decoder. */
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "parser.h"

#define IPV4_MIN_HDR 20
#define IPV4_MAX_HDR 60

static inline uint8_t tcp_flags_from_byte(uint8_t flag_byte) {
    uint8_t f = 0;
    if (flag_byte & 0x01) f |= TCP_FLAG_FIN;
    if (flag_byte & 0x02) f |= TCP_FLAG_SYN;
    if (flag_byte & 0x04) f |= TCP_FLAG_RST;
    if (flag_byte & 0x08) f |= TCP_FLAG_PSH;
    if (flag_byte & 0x10) f |= TCP_FLAG_ACK;
    if (flag_byte & 0x20) f |= TCP_FLAG_URG;
    return f;
}

int parse_packet(const uint8_t *data, size_t len, parsed_packet_t *pkt) {
    if (!data || !pkt) return -1;
    if (len < sizeof(struct ether_header)) return -1;

    const struct ether_header *eth = (const struct ether_header *)data;
    memcpy(pkt->dst_mac, eth->ether_dhost, 6);
    memcpy(pkt->src_mac, eth->ether_shost, 6);
    pkt->ethertype = ntohs(eth->ether_type);

    if (pkt->ethertype != ETHERTYPE_IP) return 0;

    size_t offset = sizeof(struct ether_header);
    if (len < offset + IPV4_MIN_HDR) return -1;

    const struct iphdr *ip = (const struct iphdr *)(data + offset);

    if (ip->version != 4) return -1;

    size_t ip_hdr_len = (size_t)(ip->ihl * 4);
    if (ip_hdr_len < IPV4_MIN_HDR || ip_hdr_len > IPV4_MAX_HDR) return -1;
    if (len < offset + ip_hdr_len) return -1;

    pkt->src_ip       = ntohl(ip->saddr);
    pkt->dst_ip       = ntohl(ip->daddr);
    pkt->protocol     = ip->protocol;
    pkt->ttl          = ip->ttl;
    pkt->ip_total_len = ntohs(ip->tot_len);
    pkt->ip_version   = 4;
    pkt->has_ip       = 1;

    uint16_t frag_off_host = ntohs(ip->frag_off);
    if ((frag_off_host & 0x1FFF) != 0) return 0;

    offset += ip_hdr_len;

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        if (len < offset + sizeof(struct tcphdr)) return -1;
        const uint8_t *tcp_bytes = data + offset;
        uint16_t src, dst;
        memcpy(&src, tcp_bytes + 0, 2);
        memcpy(&dst, tcp_bytes + 2, 2);
        pkt->src_port = ntohs(src);
        pkt->dst_port = ntohs(dst);
        pkt->tcp_flags = tcp_flags_from_byte(tcp_bytes[13]);
        pkt->has_transport = 1;
        break;
    }
    case IPPROTO_UDP: {
        if (len < offset + sizeof(struct udphdr)) return -1;
        const uint8_t *udp_bytes = data + offset;
        uint16_t src, dst;
        memcpy(&src, udp_bytes + 0, 2);
        memcpy(&dst, udp_bytes + 2, 2);
        pkt->src_port = ntohs(src);
        pkt->dst_port = ntohs(dst);
        pkt->has_transport = 1;
        break;
    }
    case IPPROTO_ICMP: {
        if (len < offset + sizeof(struct icmphdr)) return -1;
        const uint8_t *icmp_bytes = data + offset;
        pkt->icmp_type = icmp_bytes[0];
        pkt->icmp_code = icmp_bytes[1];
        pkt->has_transport = 1;
        break;
    }
    default:
        break;
    }

    return 0;
}
