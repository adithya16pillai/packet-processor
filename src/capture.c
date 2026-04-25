/* AF_PACKET raw socket setup and recv wrapper. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "capture.h"

int capture_open(const char *interface) {
    if (!interface) { errno = EINVAL; return -1; }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    unsigned int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "capture: interface not found: %s\n", interface);
        close(sockfd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)ifindex;

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        close(sockfd);
        return -1;
    }

    int rcvbuf = 4 * 1024 * 1024;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    return sockfd;
}

int capture_set_promisc(int sockfd, const char *interface, int enable) {
    unsigned int ifindex = if_nametoindex(interface);
    if (ifindex == 0) { errno = ENODEV; return -1; }

    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = (int)ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;

    int op = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;
    if (setsockopt(sockfd, SOL_PACKET, op, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt(PACKET_MR_PROMISC)");
        return -1;
    }
    return 0;
}

ssize_t capture_next(int sockfd, uint8_t *buf, size_t buflen) {
    ssize_t len = recv(sockfd, buf, buflen, 0);
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return -1;
    }
    return len;
}

void capture_close(int sockfd) {
    if (sockfd >= 0) close(sockfd);
}
