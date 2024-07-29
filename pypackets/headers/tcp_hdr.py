from dataclasses import dataclass
from random import randrange
import socket
import struct
from typing import Callable, Literal, Optional

from pypackets.headers.layers import Layer

@dataclass(frozen=True, slots=True)
class TCPFlags:
  fin: int = 0
  syn: int = 0
  rst: int = 0
  psh: int = 0
  ack: int = 0
  ugr: int = 0

  def __int__(self) -> int:
    return self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.ugr << 5)

@dataclass
class TCPHeader:
  sport: int
  dport: int
  seq: int = randrange(1, 2**32-1)
  ack_seq: int = 0
  offset_res: int = 80
  flags: int = int(TCPFlags(syn=1))
  window: int = socket.htons(14600)
  tcp_check: int = 0
  urg_ptr: int = 0

@dataclass
class TCPLayer:
  tcp_hdr: TCPHeader

  layer = Layer.Transport
  pack_string = "!HHLLBBHHH"
  byte_size: int = 20
  spoof_fields: Optional[set[Literal["sport"]]] = None
  culc_check: Optional[Callable[[bytearray, bytes], int]] = None

  def pack_hdr(self, check: int, buf: bytearray, offset: int) -> None:
    struct.pack_into(self.pack_string, buf, offset, self.tcp_hdr.sport, 
                    self.tcp_hdr.dport, self.tcp_hdr.seq, self.tcp_hdr.ack_seq, 
                    self.tcp_hdr.offset_res, self.tcp_hdr.flags,
                    self.tcp_hdr.window, check, self.tcp_hdr.urg_ptr
    )
  
  def to_buffer(self, buf, offset: int) -> int:
    end_size = offset+self.byte_size
    if not self.spoof_fields: 
      if not hasattr(self, "usual_pkt_buf"):
        src_ip = buf[offset-8:offset-4]
        self.usual_pkt_buf = bytearray(self.byte_size)
        self.pack_hdr(0, self.usual_pkt_buf, 0)
        if self.culc_check: check = self.culc_check(self.usual_pkt_buf, src_ip)
        else: check = self.tcp_hdr.tcp_check
        self.pack_hdr(check, self.usual_pkt_buf, 0)
      buf[offset:end_size] = self.usual_pkt_buf
      return end_size
    
    for field in self.spoof_fields:
      match field:
        case "sport": self.tcp_hdr.sport = self.tcp_hdr.sport+1 if self.tcp_hdr.sport < 65535-1 else randrange(65535)
        case _: raise AttributeError(f"{self.tcp_hdr.__class__} hasn't attribute {field}.\nOr spoofing unsupported for this field")
    self.pack_hdr(0, buf, offset)
    if self.culc_check:
      src_ip = buf[offset-8:offset-4]
      check = self.culc_check(buf[offset:end_size], src_ip)
      self.pack_hdr(check, buf, offset)
    return end_size
