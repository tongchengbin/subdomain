package subdomain

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"net"
	"time"
)

func getPcapDeviceNameByIP(ip net.IP) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("获取网络设备失败: %v", err)
	}

	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if addr.IP != nil && addr.IP.Equal(ip) {
				return dev.Name, nil
			}
		}
	}
	return "", fmt.Errorf("找不到匹配 IP 的设备")
}

func getGatewayIP(localIP net.IP) (net.IP, error) {
	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("获取默认网关失败: %v", err)
	}
	return ip, nil
}

func getLocalRouteInfo(dstIP string) (iFaceName string, localIP net.IP, localMAC, gatewayMAC net.HardwareAddr, err error) {
	conn, err := net.Dial("udp", net.JoinHostPort(dstIP, "53")) // DNS 默认端口
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("创建 UDP 连接失败: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP = localAddr.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("获取接口失败: %v", err)
	}

	var iface *net.Interface
	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip.Equal(localIP) {
				iface = &i
				localMAC = i.HardwareAddr
				iFaceName, err = getPcapDeviceNameByIP(localIP)
				break
			}
		}
		if iface != nil {
			break
		}
	}

	if iface == nil {
		return "", nil, nil, nil, fmt.Errorf("未找到本地接口")
	}

	// 获取默认网关 IP
	gatewayIP, err := getGatewayIP(localIP)
	if err != nil {
		return "", nil, nil, nil, err
	}
	// 获取网关 MAC 地址
	gatewayMAC, err = ArpRequestSync(iFaceName, localIP, gatewayIP, localMAC)
	if err != nil {
		return "", nil, nil, nil, err
	}
	return iFaceName, localIP, localMAC, gatewayMAC, nil
}

func ArpRequestSync(iFaceName string, srcAddr, dstAddr net.IP, srcMac net.HardwareAddr) (net.HardwareAddr, error) {
	// 同步接口,获取网关MAC
	// 构建 ARP 请求包
	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 广播 MAC 地址
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMac,
		SourceProtAddress: srcAddr.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 目标 MAC 地址置为全 0
		DstProtAddress:    dstAddr.To4(),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, opts, &eth, &arp)
	if err != nil {
		return nil, err
	}
	handle, err := pcap.OpenLive(iFaceName, 65536, false, pcap.BlockForever)
	defer handle.Close()
	// 发送 ARP 请求包
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//defer close(packetSource.Packets()) Fished after close
	timeout := time.After(2 * time.Second)
	for {
		select {
		case packet := <-packetSource.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arpPacket, _ := arpLayer.(*layers.ARP)
				if arpPacket.Operation == layers.ARPReply && net.IP(arpPacket.SourceProtAddress).Equal(dstAddr) &&
					net.IP(arpPacket.DstProtAddress).Equal(srcAddr) {
					// 输出目标 MAC 地址
					sourceMAC := net.HardwareAddr(arpPacket.SourceHwAddress)
					return sourceMAC, nil
				}
			}
		case <-timeout:
			return nil, errors.New("get ARP Reply Timeout")
		}
	}
}

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}
