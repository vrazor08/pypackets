# sudo .venv/bin/pytest ./tests/
# Or sudo -s .venv/bin/pytest ./tests/ - for debug
import socket

from pypackets.headers.ip_hdr import IPHeader, IPLayer
from pypackets.checksum import Checksum
from tests.helpers import sniff_run, flood_run, sleeping

loopback_iface_name = "lo" # TODO: don't hardcode this iface name

class TestsSpoof:
  dst_ip_b = socket.inet_aton("1.1.1.1")
  dst_ip_str = socket.inet_ntoa(dst_ip_b)
  checksum = Checksum(dst_ip_str)
  
  def test_5_full_spoof_in_sniff_packet_raw_pkts(self):
    sniff_proc = sniff_run(TestsSpoof.dst_ip_str, loopback_iface_name, "src_ip, sport")
    sleeping()
    pkts = flood_run(5, IPLayer(IPHeader(tot_len=40, src_ip=socket.inet_aton("2.2.2.2"), dst_ip=TestsSpoof.dst_ip_b), culc_check=TestsSpoof.checksum.ip_checksum_buf), 
                    loopback_iface_name, 80, "packet_raw")
    sniff_proc.wait()
    assert(sniff_proc.returncode != 0)
    assert(pkts == 5)
  
  def test_5_full_spoof_packet_raw_pkts(self):
    sniff_proc = sniff_run(TestsSpoof.dst_ip_str, loopback_iface_name, "src_ip, sport")
    sleeping()
    pkts = flood_run(5, IPLayer(IPHeader(tot_len=40, dst_ip=TestsSpoof.dst_ip_b), spoof_fields={"src_ip"}, culc_check=TestsSpoof.checksum.ip_checksum_buf), 
                    loopback_iface_name, 80, "packet_raw")
    sniff_proc.wait()
    assert(sniff_proc.returncode == 0)
    assert(pkts == 5)
  
  def test_1500_full_spoof_raw_pkts(self):
    sniff_proc = sniff_run(TestsSpoof.dst_ip_str, loopback_iface_name, "src_ip, sport", 1500)
    sleeping()
    pkts = flood_run(1500, IPLayer(IPHeader(tot_len=40, dst_ip=TestsSpoof.dst_ip_b), spoof_fields={"src_ip"}, culc_check=TestsSpoof.checksum.ip_checksum_buf), 
                    loopback_iface_name, 80, "packet_raw")
    sniff_proc.wait()
    assert(sniff_proc.returncode == 0)
    assert(pkts == 1500)
  
  def test_1500_full_spoof_raw_inet(self):
    sniff_proc = sniff_run("127.1.1.1", loopback_iface_name, "src_ip, sport", 1500)
    sleeping()
    pkts = flood_run(1500, IPLayer(IPHeader(tot_len=40, dst_ip=socket.inet_aton("127.1.1.1")), spoof_fields={"src_ip"}), 
                    loopback_iface_name, 49000, "inet_raw")
    sniff_proc.wait()
    assert(sniff_proc.returncode == 0)
    assert(pkts == 1500)

class TestsNotSpoof:
    def test_5_not_spoofed_packet_raw_pkts(self):
      sniff_proc = sniff_run(TestsSpoof.dst_ip_str, loopback_iface_name)
      sleeping()
      pkts = flood_run(5, IPLayer(IPHeader(tot_len=40, src_ip=socket.inet_aton("2.2.2.2"), dst_ip=TestsSpoof.dst_ip_b), culc_check=TestsSpoof.checksum.ip_checksum_buf), 
                      loopback_iface_name, 80, "packet_raw")
      sniff_proc.wait()
      assert(sniff_proc.returncode == 0)
      assert(pkts == 5)
