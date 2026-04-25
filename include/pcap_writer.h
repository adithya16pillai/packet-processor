/* libpcap file format writer. */
#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

typedef struct pcap_writer pcap_writer_t;

pcap_writer_t *pcap_writer_open(const char *path);
int            pcap_writer_append(pcap_writer_t *w,
                                  const struct timespec *ts,
                                  const uint8_t *data,
                                  size_t len);
int            pcap_writer_close(pcap_writer_t *w);
uint64_t       pcap_writer_bytes(const pcap_writer_t *w);

#endif
