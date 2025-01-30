package main

import (
	"net"
	"os"
	"time"

	"github.com/kataras/golog"
	log "github.com/kataras/golog"
	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	protocolICMP = 1
)

type ICMPScanner struct {
	src net.IP

	input  chan []string
	output chan string
}

// 调大缓存区
// sysctl net.core.rmem_max
// sysctl net.core.wmem_max

func NewICMPScanner(input chan []string, output chan string) *ICMPScanner {
	localIP := getLocalIP()
	s := &ICMPScanner{
		input:  input,
		output: output,
		src:    net.ParseIP(localIP),
	}
	return s
}

func (s *ICMPScanner) Scan() {
	go s.recv()
	go s.send(s.input)
}

// send sends a single ICMP echo request packet for each ip in the input channel.
func (s *ICMPScanner) send(input chan []string) error {
	defer func() {
		time.Sleep(5 * time.Second)
		close(s.output)
		golog.Infof("send goroutine exit")
	}()

	id := os.Getpid() & 0xffff

	// 创建 ICMP 连接
	conn, err := icmp.ListenPacket("ip4:icmp", s.src.String())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// 不负责接收数据
	filter := createEmptyFilter()
	if assembled, err := bpf.Assemble(filter); err == nil {
		conn.IPv4PacketConn().SetBPF(assembled)
	}

	seq := uint16(0)
	for ips := range input {
		for _, ip := range ips {
			dst, err := net.ResolveIPAddr("ip", ip)
			if err != nil {
				golog.Fatalf("failed to resolve IP address: %v", err)
			}

			// 构造 ICMP 报文
			msg := &icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   id,
					Seq:  int(seq),
					Data: []byte("Hello, are you there!"),
				},
			}
			msgBytes, err := msg.Marshal(nil)
			if err != nil {
				golog.Errorf("failed to marshal ICMP message: %v", err)
			}

			// 发送 ICMP 报文
			_, err = conn.WriteTo(msgBytes, dst)
			if err != nil {
				golog.Errorf("failed to send ICMP message: %v", err)
			}
			seq++
		}
	}

	return nil
}

// recv receives ICMP echo reply packets and sends the source IP to the output channel.
func (s *ICMPScanner) recv() error {
	defer recover()

	id := os.Getpid() & 0xffff

	// 创建 ICMP 连接
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// 接收 ICMP 报文
	reply := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			log.Fatal(err)
		}

		// 解析 ICMP 报文
		msg, err := icmp.ParseMessage(protocolICMP, reply[:n])
		if err != nil {
			golog.Errorf("failed to parse ICMP message: %v", err)
			continue
		}

		// 打印结果
		switch msg.Type {
		case ipv4.ICMPTypeEchoReply:
			echoReply, ok := msg.Body.(*icmp.Echo)
			if !ok {
				continue
			}
			if echoReply.ID == id {
				s.output <- peer.String()
			}
		}
	}
}
