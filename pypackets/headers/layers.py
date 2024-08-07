from enum import IntEnum
import socket

class Layer(IntEnum):
  Physical = 1
  DataLink = 2
  Network = 3
  Transport = 4
  Session = 5
  Presentation = 6
  Application = 7

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
