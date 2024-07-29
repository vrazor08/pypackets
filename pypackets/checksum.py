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

  def ip_checksum_buf(self, buf: bytearray) -> int:
    s = sum(memoryview(buf).cast("H"))
    return self.culc_check_for_int(s)
  
  def tcp_checksum_buf(self, pkt_buf: bytearray, src_ip: bytes) -> int:
    if not hasattr(self, "psd_hdr_buf"): self.psd_hdr_buf = bytearray(12)
    struct.pack_into("!4s4sBBH", self.psd_hdr_buf, 0, src_ip, self.dst_ip, 0, socket.IPPROTO_TCP, len(pkt_buf))
    s = sum(memoryview(self.psd_hdr_buf).cast("H")) + sum(memoryview(pkt_buf).cast("H"))
    return self.culc_check_for_int(s)