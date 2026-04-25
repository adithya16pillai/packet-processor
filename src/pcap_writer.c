/* libpcap file writer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap_writer.h"

#define PCAP_MAGIC_US    0xa1b2c3d4u
#define PCAP_VERSION_MAJ 2
#define PCAP_VERSION_MIN 4
#define LINKTYPE_ETHERNET 1
#define SNAPLEN          65535

struct pcap_writer {
    FILE    *fp;
    uint64_t bytes;
};

struct pcap_global_header {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_record_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

pcap_writer_t *pcap_writer_open(const char *path) {
    if (!path) return NULL;

    FILE *fp = fopen(path, "wb");
    if (!fp) return NULL;

    struct pcap_global_header gh = {
        .magic_number  = PCAP_MAGIC_US,
        .version_major = PCAP_VERSION_MAJ,
        .version_minor = PCAP_VERSION_MIN,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = SNAPLEN,
        .network       = LINKTYPE_ETHERNET,
    };
    if (fwrite(&gh, sizeof(gh), 1, fp) != 1) { fclose(fp); return NULL; }

    pcap_writer_t *w = calloc(1, sizeof(*w));
    if (!w) { fclose(fp); return NULL; }
    w->fp    = fp;
    w->bytes = sizeof(gh);
    return w;
}

int pcap_writer_append(pcap_writer_t *w,
                       const struct timespec *ts,
                       const uint8_t *data,
                       size_t len) {
    if (!w || !ts || !data) return -1;
    if (len > SNAPLEN) len = SNAPLEN;

    struct pcap_record_header rh = {
        .ts_sec   = (uint32_t)ts->tv_sec,
        .ts_usec  = (uint32_t)(ts->tv_nsec / 1000),
        .incl_len = (uint32_t)len,
        .orig_len = (uint32_t)len,
    };
    if (fwrite(&rh, sizeof(rh), 1, w->fp) != 1) return -1;
    if (len && fwrite(data, 1, len, w->fp) != len) return -1;
    w->bytes += sizeof(rh) + len;
    return 0;
}

int pcap_writer_close(pcap_writer_t *w) {
    if (!w) return 0;
    if (w->fp) { fflush(w->fp); fclose(w->fp); }
    free(w);
    return 0;
}

uint64_t pcap_writer_bytes(const pcap_writer_t *w) {
    return w ? w->bytes : 0;
}
