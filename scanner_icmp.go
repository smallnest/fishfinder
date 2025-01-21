package main

import (
	"net"
	"os"
	"sync"

	"github.com/kataras/golog"
	log "github.com/kataras/golog"
	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ICMPScanner struct {
	src         net.IP
	wg          *sync.WaitGroup
	concurrency int
}

func NewICMPScanner(localIP string, concurrency int, wg *sync.WaitGroup) *ICMPScanner {
	s := &ICMPScanner{
		src:         net.ParseIP(localIP),
		concurrency: concurrency,
		wg:          wg,
	}
	return s
}

func (s *ICMPScanner) Scan(input chan []string) (output chan string) {
	output = make(chan string, 1024*1024)
	// go s.recv(output)

	for i := 0; i < s.concurrency; i++ {
		go s.send(input)
	}

	return output
}

// Close closes the pcap handle.
func (s *ICMPScanner) Close() {

}

// send sends a single ICMP echo request packet for each ip in the input channel.
func (s *ICMPScanner) send(input chan []string) error {
	defer s.wg.Done()

	id := os.Getpid() & 0xffff

	// 创建 ICMP 连接
	conn, err := icmp.ListenPacket("ip4:icmp", s.src.String())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	pconn := ipv4.NewPacketConn(conn)
	// 不负责接收数据
	filter := createEmptyFilter()
	if assembled, err := bpf.Assemble(filter); err == nil {
		pconn.SetBPF(assembled)
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
