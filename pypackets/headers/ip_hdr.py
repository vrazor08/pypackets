from dataclasses import dataclass
from random import getrandbits, randrange
import socket
import struct
from typing import Callable, Literal, Optional

import netifaces as net

from pypackets.headers.layers import Layer

@dataclass
class IPHeader:
  ihl_ver: int = 69
  tos: int = 0
  tot_len: int = 0
  _id: int = 0
  frag_off: int = 0
  ttl: int = 64
  proto: int = socket.IPPROTO_TCP
  ip_check: int = 0
  src_ip: Optional[bytes] = None
  dst_ip: bytes = None
     
  @staticmethod
  def get_src_ip(iface: str): return net.ifaddresses(iface)[net.AF_INET][0]["addr"]


@dataclass
class IPLayer:
  ip_hdr: IPHeader

  layer = Layer.Network
  byte_size: int = 20
  pack_string: str = "!BBHHHBBH4s4s"
  spoof_fields: Optional[set[Literal["_id", "src_ip"]]] = None
  culc_check: Optional[Callable[[bytearray], int]] = None

  def pack_hdr(self, check: int, buf: bytearray, offset: int) -> None:
    """
    pack ip header if not pack_option, pack into bytes.
    if pack_option, pack into pack_option[0] with pack_option[1] offset
    """
    struct.pack_into(self.pack_string, buf, offset, self.ip_hdr.ihl_ver, self.ip_hdr.tos, 
                    self.ip_hdr.tot_len, self.ip_hdr._id, self.ip_hdr.frag_off, self.ip_hdr.ttl, self.ip_hdr.proto, 
                    check, self.ip_hdr.src_ip, self.ip_hdr.dst_ip
    )

  def to_buffer(self, buf: bytearray, offset: int) -> int:
    end_size = offset+self.byte_size
    if not self.spoof_fields:
      if not hasattr(self, "usual_pkt_buf"):
        self.usual_pkt_buf = bytearray(self.byte_size)
        self.pack_hdr(0, self.usual_pkt_buf, 0)
        if self.culc_check: check = self.culc_check(self.usual_pkt_buf)
        else: check = self.ip_hdr.ip_check
        self.pack_hdr(check, self.usual_pkt_buf, 0)        
      buf[offset:end_size] = self.usual_pkt_buf # TODO: don't copy
      return end_size
    for field in self.spoof_fields:
      match field:
        case "_id": self.ip_hdr._id = self.ip_hdr._id + 1 if self.ip_hdr._id > 65535-1 else randrange(65535)
        case "src_ip": self.ip_hdr.src_ip = struct.pack("!I", getrandbits(32))
        case _: raise AttributeError(f"{self.ip_hdr.__class__} hasn't attribute {field}.\nOr spoofing unsupported for this field")
    self.pack_hdr(0, buf, offset)
    if self.culc_check:
      check = self.culc_check(buf[offset:end_size])
      self.pack_hdr(check, buf, offset)
    return end_size
