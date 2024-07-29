from ctypes import CDLL, POINTER, c_int, c_uint, c_void_p
import ctypes
import errno
from pathlib import Path
import socket

def errno_restype(sendmmsg_lib): sendmmsg_lib.__errno_location.restype = POINTER(c_int)
def get_errno(sendmmsg_lib): return sendmmsg_lib.__errno_location().contents.value

class ErrnoException(Exception):
  def __init__(self, errno_code: int):
    self.errno_code = errno_code
    self.message = f"Errno code error. Errno: {errno_code}, means {errno.errorcode.get(errno_code, "something...")}"
    super().__init__(self.message)

class SendMmsg:
  def __init__(self):
    self.sendmmsg_lib_path = str(Path(__file__).resolve().parent) + "/bin/sendmmsg.so"
    sendmmsg_lib = CDLL(self.sendmmsg_lib_path)
    errno_restype(sendmmsg_lib)
    self.sendmmsg_lib = sendmmsg_lib
    self.sendmmsg_lib.write_batch.argtypes = [c_int, c_void_p, c_int, c_uint]
    self.sendmmsg_lib.write_batch.restype = c_int

  @staticmethod
  def from_mv(mv:memoryview, to_type=ctypes.c_char):
    return ctypes.cast(ctypes.addressof(to_type.from_buffer(mv)), ctypes.POINTER(to_type * len(mv))).contents
  
  def get_max_sendmmsg_pkts_count(self) -> int:
    return self.sendmmsg_lib.get_iov_max()
    
  def fast_call(self, fd: socket.socket, buf: bytearray, pkt_size: int):
    """buf is buffer of packets. New packet must start with pkt_size step"""
    pkts_count = len(buf) // pkt_size
    # buf_2d = buf.cast("B", shape=[pkts_count, pkt_size])
    c_pkt_array = (c_void_p*pkts_count).from_buffer(buf)
    pkt_sent = self.sendmmsg_lib.write_batch(fd.fileno(), c_pkt_array, pkts_count, pkt_size)
    err_code = get_errno(self.sendmmsg_lib)
    if err_code != 0: raise ErrnoException(err_code)
    return pkt_sent