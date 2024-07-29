// sudo ./sniff -dst_ip 1.1.1.1
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const defaultSnapLen = 56

type Param struct {
	iface       string
	proto       layers.IPProtocol
	filter      string
	dstIP       net.IP
	pktsCount   int
	snapLen     int32
	duration    time.Duration
	opts        map[gopacket.LayerType]gopacket.SerializeOptions
	spoofFields map[gopacket.LayerType][]string
}

func initParams() (Param, error) {
	dst_ip := flag.String("dst_ip", "", "dst_ip for filtering")
	spoofFields := flag.String("sf", "", "spoof fields separated by comma. For example: src_ip,sport")
	iface := flag.String("i", "lo", "interface for filtering")
	proto := flag.String("proto", "tcp", "protocol for filtering")
	pktsCount := flag.Int("pkts_count", 5, "count sniff packets")
	snapLen := flag.Int("snap_len", defaultSnapLen, "max packet size")
	duration := flag.Duration("timeout", time.Second*5, "timeout for one packet sniffing")

	flag.Parse()
	filter := *proto
	opts := make(map[gopacket.LayerType]gopacket.SerializeOptions, 2)
	opts[layers.LayerTypeIPv4] = gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	if *dst_ip != "" {
		filter += " and dst " + *dst_ip
	} else {
		return Param{}, errors.New("dst_ip cannot be None")
	}
	fmt.Println("Params:", *dst_ip, *iface, *proto, duration, *pktsCount, *snapLen, filter)
	var protocol layers.IPProtocol
	switch strings.ToUpper(*proto) {
	case "TCP":
		protocol = layers.IPProtocolTCP
		opts[layers.LayerTypeTCP] = gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
	default:
		return Param{}, fmt.Errorf("unknown protocol %s", *proto)
	}
	spoofSlice := strings.Split(*spoofFields, ",")
	spoofFieldsMap := make(map[gopacket.LayerType][]string, 3)
	for _, field := range spoofSlice {
		switch field {
		case "src_ip":
			spoofFieldsMap[layers.LayerTypeIPv4] = append(spoofFieldsMap[layers.LayerTypeEthernet], "src_ip")
		case "sport":
			spoofFieldsMap[layers.LayerTypeTCP] = append(spoofFieldsMap[layers.LayerTypeTCP], "sport")
		case "":
			continue
		default:
			return Param{}, fmt.Errorf("unknown spoof filed: %s", field)
		}
	}
	log.Println("Spoof fields: ", spoofFieldsMap)
	return Param{
		iface:       *iface,
		proto:       protocol,
		filter:      filter,
		dstIP:       net.IP(*dst_ip),
		pktsCount:   *pktsCount,
		snapLen:     int32(*snapLen),
		duration:    *duration,
		opts:        opts,
		spoofFields: spoofFieldsMap,
	}, nil
}
func initLayerParams(params Param) LayerParams {
	ethPatams := EthCheckParams{
		iface: params.iface,
	}
	ipParams := IPcheckParams{
		dst_ip:       params.dstIP,
		proto:        params.proto,
		ipSpoofField: params.spoofFields[layers.LayerTypeIPv4],
		opts:         params.opts[layers.LayerTypeIPv4],
	}
	tcpParams := TCPcheckParams{
		tcpSpoofFields: params.spoofFields[layers.LayerTypeTCP],
		opts:           params.opts[layers.LayerTypeTCP],
	}
	return LayerParams{
		ethParams: ethPatams,
		ipParams:  ipParams,
		tcpParams: tcpParams,
	}
}
func initHandle(iface string, snapLen int32, filter string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, snapLen, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, err
	}
	return handle, nil
}

func sniffPackets(ctx context.Context, packets *gopacket.PacketSource, params Param) (int, error) {
	var i int
	buf_3l := gopacket.NewSerializeBufferExpectedSize(0, defaultSnapLen)
	buf_4l := gopacket.NewSerializeBufferExpectedSize(0, defaultSnapLen)
	layerParam := initLayerParams(params)
	defer buf_3l.Clear()
	defer buf_4l.Clear()
	for {
		select {
		case pkt := <-packets.Packets():
			// TODO: check each packet in goroutine
			i++
			ethHdr, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			if !ok {
				return i, errors.New("EthernetHeader error")
			}

			ipHdr, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok {
				return i, errors.New("IPHeader error")
			}

			tcpHdr, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !ok {
				return i, errors.New("TCPHeader error")
			}

			if err := layerParam.ethParams.checkEthHdr(ethHdr); err != nil {
				return i, err
			}
			if err := layerParam.ipParams.checkIPHdr(ipHdr, buf_3l); err != nil {
				log.Println("IP Buf error trace:", buf_3l.Bytes())
				return i, err
			}
			if err := layerParam.tcpParams.checkTCPHdr(tcpHdr, ipHdr, buf_4l); err != nil {
				log.Println("TCP Buf error trace:", buf_4l.Bytes())
				return i, err
			}
			if i == params.pktsCount {
				return i, nil
			}
			buf_3l.Clear()
			buf_4l.Clear()
		case <-ctx.Done():
			return i, ctx.Err()
		}
	}
}
func main() {
	log.SetOutput(os.Stderr)
	log.Println("sniff starting...")
	params, err := initParams()
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), params.duration)
	defer cancel()
	handle, err := initHandle(params.iface, params.snapLen, params.filter)
	if err != nil {
		panic(err)
	}
	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	pktsCount, err := sniffPackets(ctx, packets, params)
	if err != nil {
		err = fmt.Errorf("%w\nsniff packets count: %d", err, pktsCount)
		panic(err)
	}
	if pktsCount != params.pktsCount {
		err = fmt.Errorf("uncorrect sniff packets count, recieved: %d, need to recieve: %d", pktsCount, params.pktsCount)
		panic(err)
	}
	log.Println("sniff packets count:", pktsCount)
}
