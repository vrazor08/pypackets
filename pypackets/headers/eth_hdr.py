from dataclasses import dataclass
import ipaddress
from socket import ETHERTYPE_IP
import struct

from getmac import get_mac_address
import netifaces as net

from pypackets.headers.layers import Layer

@dataclass(slots=True)
class EthernetHeader:
  dst_mac: bytes
  src_mac: bytes
  ethertype: int = ETHERTYPE_IP

  @staticmethod
  def get_src_mac(iface: str) -> str: return net.ifaddresses(iface)[net.AF_LINK][0]["addr"]

  @staticmethod
  def get_dst_mac(iface: str) -> str:
    getway_ip = net.gateways()["default"][net.AF_INET][0]
    return get_mac_address(ip=getway_ip)

  @staticmethod
  def _mac_to_bytes(mac: str) -> bytes:
    r"convert mac with : to bytes, example 00:00:00:00:00:00 -> b'\x00\x00\x00\x00\x00\x00'"
    return bytes.fromhex(mac.replace(":", ""))


@dataclass(slots=True)
class EthernetLayer:
  eth_hdr: EthernetHeader

  layer: int = Layer.DataLink
  byte_size: int = 14
  pack_string = "!6s6sH"

  __cached_eth_hdr = bytearray(byte_size)

  def __post_init__(self):
    struct.pack_into(self.pack_string, self.__cached_eth_hdr, 0, self.eth_hdr.dst_mac, self.eth_hdr.src_mac, self.eth_hdr.ethertype)

  @staticmethod
  def get_default_interface(dst_ip: str) -> str:
    if ipaddress.IPv4Address(dst_ip).is_loopback:
      for iface in net.interfaces():
        addr = net.ifaddresses(iface)
        if net.AF_INET in addr and addr[net.AF_INET][0]['addr'] == '127.0.0.1': return iface
    return net.gateways()["default"][net.AF_INET][1]

  def to_buffer(self, buf, offset: int) -> int:
    # struct.pack_into(self.pack_string, buf, offset, self.eth_hdr.dst_mac, self.eth_hdr.src_mac, self.eth_hdr.ethertype)
    end_size = offset + self.byte_size
    buf[offset:end_size] = self.__cached_eth_hdr
    return end_size
