/* BPF-style filter rule parsing and matching. */
#ifndef FILTER_H
#define FILTER_H

#include "common.h"

int filter_parse(const char *rule_str, filter_rule_t *rule);
int filter_match(const parsed_packet_t *pkt,
                 const filter_rule_t   *rules,
                 int                    count);
void filter_describe(const filter_rule_t *rule, char *out, size_t out_len);

#endif
