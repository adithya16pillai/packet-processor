/* ASCII table and JSON formatters for flow statistics. */
#ifndef STATS_H
#define STATS_H

#include <stdio.h>
#include "flow_table.h"

void stats_print_flows(const flow_table_t *ft, FILE *out);
void stats_print_flows_json(const flow_table_t *ft, FILE *out);
void stats_print_summary(FILE *out,
                         uint64_t total_packets,
                         uint64_t matched_packets,
                         const flow_table_t *ft);

#endif
