from enum import IntEnum
from socket import socket
from typing import Callable, Optional, Protocol, TypeVar
import time

from pypackets.headers.layers import Layer
from pypackets.send_pkt import _send_af_packet, _send_inet_raw
from pypackets.benchmark.benchmark import Limitation

class HasLayerField(Protocol): 
  layer: Layer
  def to_buffer(self, buf: bytearray, offset: int) -> int: ...

T = TypeVar('T', bound=HasLayerField)
SendFunc = Callable[[socket, bytearray], int]

class SendMode(IntEnum):
  ByOnePacket=1
  ByManyPackets=2

SockDefaultSendFuncs = {
  "inet_raw":   (_send_inet_raw, SendMode.ByOnePacket),
  "packet_raw": (_send_af_packet, SendMode.ByManyPackets),
  "packet_mmap": None,
  "xdp":        None,
}

class Packet:
  def __init__(self, *headers: T, fd_type: str, pkts_max: int = 1024, pkt_len: int = 54, _sorted: bool = False):
    self._sorted = _sorted
    self.headers = list(headers)
    if not self._sorted: self.headers.sort(key=lambda x: x.layer.value)
    self.pkts_max = pkts_max
    self.pkt_len = pkt_len
    self.fd_type = fd_type # TODO: get this value by fd

  def to_buffer(self, buf, offset: int) -> int:
    for header in self.headers: offset = header.to_buffer(buf, offset)
    return offset

  def __repr__(self): return f"{self.__class__}: {self.headers}"

  def __str__(self): 
    pkt = f"{self.__class__}: [\n"
    for header in self.headers: pkt += f"{header},\n"
    pkt += "]"
    return pkt

  def _create_pkts_buf(self, count: int) -> bytearray:
    buf = bytearray(count*self.pkt_len)
    offset = 0
    for i in range(count): offset = self.to_buffer(buf, offset)
    return buf

  def send_pkts(self, fd: socket, limit: Limitation,
                send_func: Optional[SendFunc] = None, send_mode: Optional[SendMode] = None, 
                **kwargc) -> int:
    if not send_func: send_func = SockDefaultSendFuncs[self.fd_type][0]
    assert(send_func and "not implemented")
    if not send_mode: send_mode = SockDefaultSendFuncs[self.fd_type][1]

    if limit.count:
      if send_mode == SendMode.ByManyPackets:
        return send_func(fd, self._create_pkts_buf(limit.count), **kwargc)
      s = 0
      for i in range(limit.count): 
        s += send_func(fd, self._create_pkts_buf(self.pkts_max), **kwargc)
      return s
    elif limit.by_time:
      s = 0
      try:
        start = time.perf_counter()
        while True: 
          s += send_func(fd, self._create_pkts_buf(self.pkts_max), **kwargc)
          if time.perf_counter() - start >= limit.by_time: raise TimeoutError
      except (TimeoutError, KeyboardInterrupt): return s
    elif limit.forever:
      s = 0
      while True:
        try: 
          s += send_func(fd, self._create_pkts_buf(self.pkts_max), **kwargc)
        except KeyboardInterrupt: return s
    else: raise ValueError(f"Unknown limit: {limit}")

