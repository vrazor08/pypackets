from enum import Enum
import socket

class Layer(Enum):
  Physical: int = 1
  DataLink: int = 2
  Network: int = 3
  Transport: int = 4
  Session: int = 5
  Presentation: int = 6
  Application: int = 7

def _create_af_inet_raw_socket() -> socket.socket:
  raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
  # raw_socket.setblocking(False)
  return raw_socket

def _create_af_packet_socket(interface: str) -> socket.socket:
  # sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ETH_P_ALL)
  sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.ETHERTYPE_IP))
  sock.bind((interface, 0))
  return sock