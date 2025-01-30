package main

import (
	"flag"
	"strings"
	"time"

	"github.com/kataras/golog"
	"github.com/smallnest/fishfinding"
)

var (
	protocol = flag.String("p", "icmp", "The protocol to use (icmp, tcp or udp)")
	srcPort  = flag.Int("s", 12345, "The source port to use")
	dstPort  = flag.Int("d", 9000, "The destination port to use")
)

// 嵌入ip.sh

func main() {
	flag.Parse()

	input := make(chan []string, 1024)
	output := make(chan string, 1024)
	scanner := fishfinding.NewTCPScanner(*srcPort, *dstPort, input, output) // 改用 TCP 扫描器

	var total int
	var alive int

	golog.Infof("start scanning")

	start := time.Now()
	// 将待探测的IP发送给send goroutine
	go func() {
		lines := fishfinding.ReadAvailableIPList()
		for _, line := range lines {
			// [INFO] 2025/01/26 20:58 1.27.222.121 is alive
			items := strings.Fields(line)
			if len(items) < 6 {
				continue
			}
			line := items[3]

			ips := fishfinding.Cidr2IPList(line)
			input <- ips
			total += len(ips)
		}
		close(input)
	}()

	// 启动 send goroutine
	scanner.Scan()

	// 接收 send goroutine 发送的结果, 直到发送之后5秒结束
	for ip := range output {
		golog.Infof("%s is alive", ip)
		alive++
	}

	golog.Infof("total: %d, alive: %d, time: %v", total, alive, time.Since(start))
}
