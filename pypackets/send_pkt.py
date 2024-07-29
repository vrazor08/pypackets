import socket

def _send_af_packet(fd: socket.socket, buf: bytearray, pkt_size: int, fastmmsg, iov_max: int = 1024) -> int:
  pkt_sent = 0
  pkts_count = len(buf) // pkt_size
  iterations = pkts_count // iov_max
  if iov_max >= pkts_count: return fastmmsg(fd, buf, pkt_size)
  for i in range(iterations):
    pkt_sent += fastmmsg(fd, buf[i*iov_max*pkt_size:(i+1)*iov_max*pkt_size], pkt_size)
  end = (pkts_count) - (iterations*iov_max)
  if end > 0: pkt_sent += fastmmsg(fd, buf[iterations*iov_max*pkt_size:], pkt_size)
  return pkt_sent

def _send_inet_raw(fd: socket.socket, pkt: bytearray, dst_ip: str, dport: int):
  bytes_sent = fd.sendto(pkt, (dst_ip, dport))
  pkt_sent = len(pkt) / bytes_sent
  assert(int(pkt_sent) == pkt_sent)
  return int(pkt_sent)
