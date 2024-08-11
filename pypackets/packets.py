from enum import IntEnum
from socket import socket
from typing import Callable, Concatenate, Literal, Optional, Protocol, ParamSpec
import time

from pypackets.send_pkt import _send_af_packet, _send_inet_raw
from pypackets.benchmark.benchmark import Limitation

class HasLayerField(Protocol):
  layer: int
  def to_buffer(self, buf: bytearray, offset: int) -> int: ...

P = ParamSpec('P')
SendFunc = Callable[Concatenate[socket, bytearray, P], int]

class SendMode(IntEnum):
  ByOnePacket=1
  ByManyPackets=2

SockDefaultSendFuncs = {
  "inet_raw"   : (_send_inet_raw, SendMode.ByOnePacket),
  "packet_raw" : (_send_af_packet, SendMode.ByManyPackets),
  "packet_mmap": None,
  "xdp"        : None,
}

class Packet:
  def __init__(self, *headers: HasLayerField, fd_type: Literal["inet_raw", "packet_raw"], pkts_max: int = 1024, pkt_len: int = 54):
    self.headers = headers
    self.pkts_max = pkts_max
    self.pkt_len = pkt_len
    self.fd_type = fd_type # TODO: get this value by fd
    self.__is_spoof_pkt = False
    for header in self.headers:
      if hasattr(header, "spoof_fields") and getattr(header, "spoof_fields") is not None: self.__is_spoof_pkt = True; break

  def to_buffer(self, buf, offset: int) -> int:
    for header in self.headers: offset = header.to_buffer(buf, offset)
    return offset

  def __repr__(self): return f"{self.__class__}: {self.headers}"

  def __str__(self):
    pkt = f"{self.__class__}: [\n"
    for header in self.headers: pkt += f"{header},\n"
    pkt += "]"
    return pkt

  def _create_pkts_buf(self, count: int, ret_time: bool = False) -> bytearray | tuple[bytearray, float]:
    start = time.perf_counter()
    buf = bytearray(count*self.pkt_len)
    offset = 0
    for _ in range(count): offset = self.to_buffer(buf, offset)
    if not ret_time: return buf
    return buf, time.perf_counter() - start

  def send_pkts(self, fd: socket, limit: Limitation, dst_ip: Optional[str] = None, dport: Optional[int] = None,
                sendmmsg: Optional[Callable[[socket, bytearray, int, int], int]] = None) -> int | tuple[int, float]:
    match self.fd_type:
      case "inet_raw":
        send_func = _send_inet_raw
        if dst_ip and dport: send_func_argc = (dst_ip, dport)
        else: raise AttributeError("dst_ip and dport cannot be None for inet_raw socket type")
        send_mode = SendMode.ByOnePacket
      case "packet_raw":
        send_func = _send_af_packet
        if sendmmsg: send_func_argc = (self.pkt_len, sendmmsg, self.pkts_max, int(not self.__is_spoof_pkt))
        else: raise AttributeError("sendmmsg cannot be None for packet_raw socket type")
        send_mode = SendMode.ByManyPackets
      case _ as sock:
        raise AttributeError(f"Unknown socket type: {sock}")

    if limit.count:
      if send_mode == SendMode.ByManyPackets: return send_func(fd, self._create_pkts_buf(limit.count), *send_func_argc) # type: ignore
      s = 0
      for i in range(limit.count): s += send_func(fd, self._create_pkts_buf(self.pkts_max), *send_func_argc) # type: ignore
      return s
    elif limit.by_time:
      s = 0
      try:
        start = time.perf_counter()
        while True:
          s += send_func(fd, self._create_pkts_buf(self.pkts_max), *send_func_argc) # type: ignore
          if time.perf_counter() - start >= limit.by_time: raise TimeoutError
      except (TimeoutError, KeyboardInterrupt): return s
    elif limit.bench:
      s, t = 0, 0
      try:
        start = time.perf_counter()
        while True:
          ans = self._create_pkts_buf(self.pkts_max, ret_time=True)
          t += ans[1]
          s += send_func(fd, ans[0], *send_func_argc) # type: ignore
          if time.perf_counter() - start >= limit.bench: raise TimeoutError
      except (TimeoutError, KeyboardInterrupt): return s, t
    elif limit.forever:
      s = 0
      while True:
        try:
          s += send_func(fd, self._create_pkts_buf(self.pkts_max), *send_func_argc) # type: ignore
        except KeyboardInterrupt: return s
    else: raise AttributeError(f"Unknown limit: {limit}")
