/* AF_PACKET raw socket API. */
#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

int capture_open(const char *interface);
int capture_set_promisc(int sockfd, const char *interface, int enable);
ssize_t capture_next(int sockfd, uint8_t *buf, size_t buflen);
void capture_close(int sockfd);

#endif
