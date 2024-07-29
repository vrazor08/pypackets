#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

int write_batch(int fd, void* pkts, int pkt_count, unsigned int pkt_len) {
  // printf("write_batch\npkt_count: %d, pkt len: %u\n", pkt_count, pkt_len);
  // TODO: add border check because now it super unsafe
  unsigned char* pkts_buf = (unsigned char*)pkts;
  struct iovec   msgs[pkt_count];
  struct mmsghdr send_msg[pkt_count];
  memset(send_msg, 0, sizeof(send_msg));
  for (int i = 0; i < pkt_count; i++) {
    memset(&msgs[i], 0, sizeof(msgs[i]));
    msgs[i].iov_base = pkts_buf + i*pkt_len;
    msgs[i].iov_len = pkt_len;
    send_msg[i].msg_hdr.msg_iov = &msgs[i];
    send_msg[i].msg_hdr.msg_iovlen = 1;
  }
 return sendmmsg(fd, send_msg, pkt_count, 0);
}

int get_iov_max(void) { return UIO_MAXIOV; }