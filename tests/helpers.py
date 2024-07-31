from pathlib import Path
import subprocess
import socket
import sys
import time
from typing import Optional

from pypackets.packets import Packet
from pypackets.headers.eth_hdr import EthernetHeader, EthernetLayer
from pypackets.headers.ip_hdr import IPLayer
from pypackets.headers.tcp_hdr import TCPHeader, TCPLayer
from pypackets.headers.layers import _create_af_inet_raw_socket, _create_af_packet_socket
from pypackets.checksum import Checksum
from pypackets.syscalls.sendmmsg import SendMmsg
from pypackets.benchmark.benchmark import Limitation

TestDir = Path(__file__).resolve().parent
SleepTime = 0.4 # TODO: don't do it by time maybe by signal from go

def sniff_run(dst_ip: str, iface: str, spoof_fields: str = "", pkts_count: int = 5):
  spoof_fields = spoof_fields.replace(" ", "")
  sniffer_proc = subprocess.Popen(["./sniff/sniff",  "-dst_ip", dst_ip, "-i", iface, "-sf", spoof_fields, "-pkts_count", str(pkts_count)], cwd=TestDir)
  return sniffer_proc

def flood_run(count, ip_layer: IPLayer, iface, dport, sock, sport: Optional[int] = None) -> int:
  dst_ip = ip_layer.ip_hdr.dst_ip
  if not iface: iface = EthernetLayer.get_default_interface(dst_ip)
  else: iface = iface
  limit = Limitation(count=count)
  checksum = Checksum(dst_ip)
  tcp_spoof_fields = {"sport"} if not sport else None
  tcp: TCPLayer = TCPLayer(TCPHeader(12345, dport), spoof_fields=tcp_spoof_fields, 
                          culc_check=checksum.tcp_checksum_buf)
  match sock:
    case "inet_raw":
      fd: socket.socket = _create_af_inet_raw_socket()
      init_pkt: Packet = Packet(ip_layer, tcp, fd_type=sock, pkts_max=1, pkt_len=40, _sorted=True)
      return init_pkt.send_pkts(fd=fd, limit=limit, 
                                dst_ip=socket.inet_ntoa(dst_ip), 
                                dport=dport
      )
    case "packet_raw":
      sendmmsg = SendMmsg()
      src_mac, dst_mac = EthernetHeader.get_src_mac(iface), EthernetHeader.get_dst_mac(iface)
      eth_hdr: EthernetHeader = EthernetHeader(EthernetHeader._mac_to_bytes(dst_mac), EthernetHeader._mac_to_bytes(src_mac))
      eth = EthernetLayer(eth_hdr)
      pkts_max = sendmmsg.get_max_sendmmsg_pkts_count()
      send_func_kwargc = {"pkt_size": 54, "iov_max": pkts_max, "fastmmsg": sendmmsg.fast_call}
      init_pkt: Packet = Packet(eth, ip_layer, tcp, fd_type=sock, pkts_max=pkts_max, _sorted=True)
      fd: socket.socket = _create_af_packet_socket(iface)
      return init_pkt.send_pkts(fd=fd, limit=limit, **send_func_kwargc)

  
def sleeping():
  print("Sleeping...", file=sys.stderr)
  time.sleep(SleepTime)