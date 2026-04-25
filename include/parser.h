/* Ethernet/IPv4/TCP/UDP/ICMP header parser. */
#ifndef PARSER_H
#define PARSER_H

#include "common.h"

int parse_packet(const uint8_t *data, size_t len, parsed_packet_t *pkt);

#endif
