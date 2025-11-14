package gotun2socks

// gotun2socks 封装了 tun2socks 的核心调度逻辑：读取 TUN 设备的原始 IP
// 数据包，解析 TCP/UDP 后交给连接跟踪器处理，再通过 SOCKS5 代理写回。

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/yinghuocho/gosocks"
	"github.com/yinghuocho/gotun2socks/internal/packet"
)

const (
	// MTU 表示 TUN 设备每次可读写的最大包长，池化缓冲区同样基于该值。
	MTU = 1500
)

var (
	localSocksDialer *gosocks.SocksDialer = &gosocks.SocksDialer{
		Auth:    &gosocks.AnonymousClientAuthenticator{},
		Timeout: 1 * time.Second,
	}

	_, ip1, _ = net.ParseCIDR("10.0.0.0/8")
	_, ip2, _ = net.ParseCIDR("172.16.0.0/12")
	_, ip3, _ = net.ParseCIDR("192.168.0.0/24")
)

// Tun2Socks 将 TUN 设备与本地 SOCKS 代理绑定起来，负责维护 TCP/UDP 状态。
type Tun2Socks struct {
	dev            io.ReadWriteCloser
	localSocksAddr string
	publicOnly     bool

	// writerStopCh/ writeCh 组成单一写出口，避免多个 goroutine 并发写设备。
	writerStopCh chan bool
	writeCh      chan interface{}

	tcpConnTrackLock sync.Mutex
	tcpConnTrackMap  map[string]*tcpConnTrack

	udpConnTrackLock sync.Mutex
	udpConnTrackMap  map[string]*udpConnTrack

	dnsServers []string
	cache      *dnsCache

	wg sync.WaitGroup
}

// isPrivate 判断目的地址是否落在私网段，用于 publicOnly 模式。
func isPrivate(ip net.IP) bool {
	return ip1.Contains(ip) || ip2.Contains(ip) || ip3.Contains(ip)
}

func dialLocalSocks(localAddr string) (*gosocks.SocksConn, error) {
	return localSocksDialer.Dial(localAddr)
}

// New 初始化 Tun2Socks，对象内部会根据配置动态开启 DNS 缓存。
func New(dev io.ReadWriteCloser, localSocksAddr string, dnsServers []string, publicOnly bool, enableDnsCache bool) *Tun2Socks {
	t2s := &Tun2Socks{
		dev:             dev,
		localSocksAddr:  localSocksAddr,
		publicOnly:      publicOnly,
		writerStopCh:    make(chan bool, 10),
		writeCh:         make(chan interface{}, 10000),
		tcpConnTrackMap: make(map[string]*tcpConnTrack),
		udpConnTrackMap: make(map[string]*udpConnTrack),
		dnsServers:      dnsServers,
	}
	if enableDnsCache {
		t2s.cache = &dnsCache{
			storage: make(map[string]*dnsCacheEntry),
		}
	}
	return t2s
}

// Stop 停止读写循环，并依次通知 TCP/UDP 连接协程退出。
func (t2s *Tun2Socks) Stop() {
	t2s.writerStopCh <- true
	t2s.dev.Close()

	t2s.tcpConnTrackLock.Lock()
	defer t2s.tcpConnTrackLock.Unlock()
	for _, tcpTrack := range t2s.tcpConnTrackMap {
		close(tcpTrack.quitByOther)
	}

	t2s.udpConnTrackLock.Lock()
	defer t2s.udpConnTrackLock.Unlock()
	for _, udpTrack := range t2s.udpConnTrackMap {
		close(udpTrack.quitByOther)
	}
	t2s.wg.Wait()
}

// Run 启动 writer（写 TUN）与 reader（读 TUN）循环，常驻阻塞直至停止。
func (t2s *Tun2Socks) Run() {
	// writer
	go func() {
		t2s.wg.Add(1)
		defer t2s.wg.Done()
		for {
			select {
			case pkt := <-t2s.writeCh:
				switch pkt.(type) {
				case *tcpPacket:
					tcp := pkt.(*tcpPacket)
					t2s.dev.Write(tcp.wire)
					releaseTCPPacket(tcp)
				case *udpPacket:
					udp := pkt.(*udpPacket)
					t2s.dev.Write(udp.wire)
					releaseUDPPacket(udp)
				case *ipPacket:
					ip := pkt.(*ipPacket)
					t2s.dev.Write(ip.wire)
					releaseIPPacket(ip)
				}
			case <-t2s.writerStopCh:
				log.Printf("quit tun2socks writer")
				return
			}
		}
	}()

	// reader
	var buf [MTU]byte
	var ip packet.IPv4
	var tcp packet.TCP
	var udp packet.UDP

	t2s.wg.Add(1)
	defer t2s.wg.Done()
	for {
		n, e := t2s.dev.Read(buf[:])
		if e != nil {
			// TODO: stop at critical error
			log.Printf("read packet error: %s", e)
			return
		}
		data := buf[:n]
		e = packet.ParseIPv4(data, &ip)
		if e != nil {
			log.Printf("error to parse IPv4: %s", e)
			continue
		}
		if t2s.publicOnly {
			// 仅允许公网目的地址，常用于旁路塑型以防内网回环。
			if !ip.DstIP.IsGlobalUnicast() {
				continue
			}
			if isPrivate(ip.DstIP) {
				continue
			}
		}

		if ip.Flags&0x1 != 0 || ip.FragOffset != 0 {
			// 简易片段重组，等待最后一个分片后再继续协议解析。
			last, pkt, raw := procFragment(&ip, data)
			if last {
				ip = *pkt
				data = raw
			} else {
				continue
			}
		}

		switch ip.Protocol {
		case packet.IPProtocolTCP:
			e = packet.ParseTCP(ip.Payload, &tcp)
			if e != nil {
				log.Printf("error to parse TCP: %s", e)
				continue
			}
			t2s.tcp(data, &ip, &tcp)

		case packet.IPProtocolUDP:
			e = packet.ParseUDP(ip.Payload, &udp)
			if e != nil {
				log.Printf("error to parse UDP: %s", e)
				continue
			}
			t2s.udp(data, &ip, &udp)

		default:
			// Unsupported packets
			log.Printf("Unsupported packet: protocol %d", ip.Protocol)
		}
	}
}
