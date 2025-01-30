package fishfinding

import (
	"net"
	"os"
	"time"

	"github.com/kataras/golog"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

const (
	tcpHeaderLength = 20
)

type TCPScanner struct {
	src     net.IP
	srcPort int
	dstPort int
	input   chan string
	output  chan string
}

func NewTCPScanner(srcPort, dstPort int, input chan string, output chan string) *TCPScanner {
	localIP := GetLocalIP()
	s := &TCPScanner{
		input:   input,
		output:  output,
		src:     net.ParseIP(localIP).To4(),
		srcPort: srcPort,
		dstPort: dstPort,
	}
	return s
}

func (s *TCPScanner) Scan() {
	go s.recv()
	go s.send(s.input)
}

func (s *TCPScanner) send(input chan string) error {
	defer func() {
		time.Sleep(5 * time.Second)
		close(s.output)
		golog.Infof("send goroutine exit")
	}()

	// 创建原始套接字
	conn, err := net.ListenPacket("ip4:tcp", s.src.To4().String())
	if err != nil {
		golog.Fatal(err)
	}
	defer conn.Close()

	pconn := ipv4.NewPacketConn(conn)
	// 不接收数据
	filter := createEmptyFilter()
	if assembled, err := bpf.Assemble(filter); err == nil {
		pconn.SetBPF(assembled)
	}

	seq := uint32(os.Getpid())
	for ip := range input {
		dstIP := net.ParseIP(ip)
		if dstIP == nil {
			golog.Errorf("failed to resolve IP address %s", ip)
			continue
		}

		// 构造 TCP SYN 包
		tcpHeader := &TCPHeader{
			Source:      uint16(s.srcPort), // 源端口
			Destination: uint16(s.dstPort), // 目标端口(这里探测80端口)
			SeqNum:      seq,
			AckNum:      0,
			Flags:       0x002, // SYN
			Window:      65535,
			Checksum:    0,
			Urgent:      0,
		}

		// 计算校验和
		tcpHeader.Checksum = tcpChecksum(tcpHeader, s.src, dstIP)

		// 序列化 TCP 头
		packet := tcpHeader.Marshal()

		// 发送 TCP SYN 包
		_, err = conn.WriteTo(packet, &net.IPAddr{IP: dstIP})
		if err != nil {
			golog.Errorf("failed to send TCP packet: %v", err)
		}
	}

	return nil
}

func (s *TCPScanner) recv() error {
	defer recover()

	// 创建原始套接字
	conn, err := net.ListenPacket("ip4:tcp", s.src.To4().String())
	if err != nil {
		golog.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			golog.Fatal(err)
		}

		if n < tcpHeaderLength {
			continue
		}

		// 解析 TCP 头
		tcpHeader := ParseTCPHeader(buf[:n])

		// 检查是否是 SYN+ACK, 同时检查ACK是否和发送的seq对应
		if tcpHeader.Flags == 0x012 && tcpHeader.AckNum == tcpHeader.SeqNum+1 { // SYN + ACK
			s.output <- peer.String()
		}
	}
}

// TCP 头结构
type TCPHeader struct {
	Source      uint16
	Destination uint16
	SeqNum      uint32
	AckNum      uint32
	Offset      uint8
	Flags       uint8
	Window      uint16
	Checksum    uint16
	Urgent      uint16
}

func (h *TCPHeader) Marshal() []byte {
	// TCP 头序列化实现
	buf := make([]byte, tcpHeaderLength)

	// 填充 TCP 头字段
	buf[0] = byte(h.Source >> 8)
	buf[1] = byte(h.Source)
	buf[2] = byte(h.Destination >> 8)
	buf[3] = byte(h.Destination)
	buf[4] = byte(h.SeqNum >> 24)
	buf[5] = byte(h.SeqNum >> 16)
	buf[6] = byte(h.SeqNum >> 8)
	buf[7] = byte(h.SeqNum)
	buf[8] = byte(h.AckNum >> 24)
	buf[9] = byte(h.AckNum >> 16)
	buf[10] = byte(h.AckNum >> 8)
	buf[11] = byte(h.AckNum)
	buf[12] = byte(tcpHeaderLength << 2)
	buf[13] = h.Flags
	buf[14] = byte(h.Window >> 8)
	buf[15] = byte(h.Window)
	buf[16] = byte(h.Checksum >> 8)
	buf[17] = byte(h.Checksum)
	buf[18] = byte(h.Urgent >> 8)
	buf[19] = byte(h.Urgent)

	return buf
}

func ParseTCPHeader(data []byte) *TCPHeader {
	header := &TCPHeader{
		Source:      uint16(data[0])<<8 | uint16(data[1]),
		Destination: uint16(data[2])<<8 | uint16(data[3]),
		SeqNum:      uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		AckNum:      uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
		Offset:      data[12] >> 4,
		Flags:       data[13],
		Window:      uint16(data[14])<<8 | uint16(data[15]),
		Checksum:    uint16(data[16])<<8 | uint16(data[17]),
		Urgent:      uint16(data[18])<<8 | uint16(data[19]),
	}
	return header
}

func tcpChecksum(header *TCPHeader, srcIP, dstIP net.IP) uint16 {
	// TCP 校验和计算实现
	// ... 校验和计算逻辑 ...
	return 0
}
