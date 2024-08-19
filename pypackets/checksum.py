import struct
import socket
from typing import Callable


class Checksum:
  def __init__(self, dst_ip: bytes):
    # from scapy
    if struct.pack("H", 1) == b"\x00\x01":  # big endian
      checksum_endian_transform = lambda chk: chk
    else:
      checksum_endian_transform = lambda chk: ((chk >> 8) & 0xFF) | chk << 8
    self.checksum_endian_transform: Callable[[int], int] = checksum_endian_transform
    self.dst_ip = dst_ip

  def culc_check_for_int(self, s: int) -> int:
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    s = ~s
    return self.checksum_endian_transform(s) & 0xFFFF

class IPChecksum(Checksum):
  def __init__(self, dst_ip: bytes):
    super().__init__(dst_ip)

  def ip_checksum_buf(self, buf: bytearray) -> int:
    s = sum(memoryview(buf).cast("H"))
    return self.culc_check_for_int(s)

class TCPChecksum(Checksum):
  def __init__(self, dst_ip: bytes, tcp_hdr_buf_len: int = 0):
    self.tcp_hdr_buf_len = tcp_hdr_buf_len
    self.psd_hdr_buf = bytearray(12)
    struct.pack_into("!4s4sBBH", self.psd_hdr_buf, 0, struct.pack("!I", 0), dst_ip, 0, socket.IPPROTO_TCP,
                    self.tcp_hdr_buf_len
    )
    self.psd_hdr_sum = sum(memoryview(self.psd_hdr_buf).cast("H"))
    super().__init__(dst_ip)

  def tcp_checksum_buf(self, pkt_buf: bytearray, src_ip: bytes) -> int:
    struct.pack_into("!4s", self.psd_hdr_buf, 0, src_ip)
    s = self.psd_hdr_sum
    if not self.tcp_hdr_buf_len:
      struct.pack_into("!H", self.psd_hdr_buf, 10, len(pkt_buf))
      s += self.checksum_endian_transform(len(pkt_buf))
    src_ip_int = struct.unpack("HH", src_ip)
    s += src_ip_int[0] + src_ip_int[1] + sum(memoryview(pkt_buf).cast("H"))
    return self.culc_check_for_int(s)
