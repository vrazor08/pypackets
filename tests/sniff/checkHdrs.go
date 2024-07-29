package main

import (
	"bytes"
	"fmt"
	"net"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var lo_mac = []byte(net.HardwareAddr{0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
var prevSport layers.TCPPort
var prevSrcIP net.IP

type LayerParams struct {
	ethParams EthCheckParams
	ipParams  IPcheckParams
	tcpParams TCPcheckParams
}

type EthCheckParams struct {
	iface string
}

type IPcheckParams struct {
	dst_ip       net.IP
	proto        layers.IPProtocol
	ipSpoofField []string
	opts         gopacket.SerializeOptions
}

type TCPcheckParams struct {
	tcpSpoofFields []string
	opts           gopacket.SerializeOptions
}

func (ethParams EthCheckParams) checkEthHdr(ethHdr *layers.Ethernet) error {
	if ethParams.iface == "lo" {
		if !bytes.Equal([]byte(ethHdr.SrcMAC), lo_mac) {
			return fmt.Errorf("src mac for loopback must be 00:00:00:00:00:00, given: %s", ethHdr.SrcMAC.String())
		}
	}
	if ethHdr.EthernetType != layers.EthernetTypeIPv4 {
		return fmt.Errorf("ether type must be 0x0800, given: %d", uint16(ethHdr.EthernetType))
	}
	return nil
}

func (ipParams IPcheckParams) checkIPHdr(ipHdr *layers.IPv4, buf gopacket.SerializeBuffer) error {
	if ipHdr.DstIP.Equal(ipParams.dst_ip) {
		return fmt.Errorf("dst ip must be %s, given: %s", ipParams.dst_ip.String(), ipHdr.DstIP.String())
	}
	if ipHdr.Protocol != ipParams.proto {
		return fmt.Errorf("proto must be %s, given: %s", ipParams.proto.String(), ipHdr.Protocol.String())
	}
	if slices.Contains(ipParams.ipSpoofField, "src_ip") {
		if prevSrcIP.Equal(ipHdr.SrcIP) {
			return fmt.Errorf("uncorrect src_ip spoofing, given src_ip: %s the same as previous src_ip", ipHdr.SrcIP.String())
		}
		prevSrcIP = ipHdr.SrcIP
	}
	check := ipHdr.Checksum
	err := ipHdr.SerializeTo(buf, ipParams.opts)
	if err != nil {
		return err
	}
	if ipHdr.Checksum != check {
		return fmt.Errorf("ip checksum must be %d, given: %d", ipHdr.Checksum, check)
	}
	// fmt.Println("IP buf:", buf)
	return nil
}

func (tcpParams TCPcheckParams) checkTCPHdr(tcpHdr *layers.TCP, ipHdr *layers.IPv4, buf gopacket.SerializeBuffer) (err error) {
	tcpHdr.SetNetworkLayerForChecksum(ipHdr)
	check := tcpHdr.Checksum
	err = tcpHdr.SerializeTo(buf, tcpParams.opts)
	if err != nil {
		return err
	}
	if slices.Contains(tcpParams.tcpSpoofFields, "sport") {
		if prevSport == tcpHdr.SrcPort {
			return fmt.Errorf("uncorrect sport spoofing, given sport: %d the same as previous sport", tcpHdr.SrcPort)
		}
		prevSport = tcpHdr.SrcPort
	}
	if check != tcpHdr.Checksum {
		return fmt.Errorf("tcp checksum must be %d, given: %d", tcpHdr.Checksum, check)
	}
	// fmt.Println("TCP buf:", buf)
	return nil
}
