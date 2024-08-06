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
  _id: int = randrange(65535)
  frag_off: int = 0
  ttl: int = 64
  proto: int = socket.IPPROTO_TCP
  ip_check: int = 0
  src_ip: Optional[bytes] = None
  dst_ip: bytes = None # type: ignore

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

  __cahced_ip_hdr =  bytearray(byte_size)

  def __post_init__(self):
    if self.ip_hdr.src_ip is None: self.ip_hdr.src_ip = struct.pack("!I", 0)
    self.pack_hdr(0, self.__cahced_ip_hdr, 0)

  def pack_hdr(self, check: int, buf: bytearray, offset: int) -> None:
    struct.pack_into(self.pack_string, buf, offset, self.ip_hdr.ihl_ver, self.ip_hdr.tos,
                    self.ip_hdr.tot_len, self.ip_hdr._id, self.ip_hdr.frag_off, self.ip_hdr.ttl,
                    self.ip_hdr.proto, check, self.ip_hdr.src_ip, self.ip_hdr.dst_ip
    )

  def to_buffer(self, buf: bytearray, offset: int) -> int:
    end_size = offset+self.byte_size
    if not self.spoof_fields:
      if self.culc_check and self.__cahced_ip_hdr[self.byte_size-10:self.byte_size-8] == b'\x00\x00':
        check = self.culc_check(self.__cahced_ip_hdr)
        struct.pack_into("!H", self.__cahced_ip_hdr, self.byte_size-10, check)
      buf[offset:end_size] = self.__cahced_ip_hdr
      return end_size
    for field in self.spoof_fields:
      match field:
        case "_id":
          self.ip_hdr._id = self.ip_hdr._id + 1 if self.ip_hdr._id < 65535 else randrange(65535)
          struct.pack_into("!H", self.__cahced_ip_hdr, 4, self.ip_hdr._id)
        case "src_ip":
          self.ip_hdr.src_ip = struct.pack("!I", getrandbits(32))
          struct.pack_into("!4s", self.__cahced_ip_hdr, self.byte_size-8, self.ip_hdr.src_ip)
        case _: raise AttributeError(f"{self.ip_hdr.__class__} hasn't attribute {field}.\nOr spoofing unsupported for this field")
    buf[offset:end_size] = self.__cahced_ip_hdr
    if self.culc_check:
      check = self.culc_check(buf[offset:end_size])
      struct.pack_into("!H", buf, end_size-10, check) # -8(dst_ip, src_ip), -2(checksum)
    return end_size
