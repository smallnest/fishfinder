package main

import (
	"flag"
	"time"

	"github.com/kataras/golog"
	"github.com/smallnest/fishfinding"
)

var (
	protocol = flag.String("p", "icmp", "The protocol to use (icmp, tcp or udp)")
)

// 嵌入ip.sh

func main() {
	flag.Parse()

	input := make(chan []string, 1024)
	output := make(chan string, 1024)
	scanner := fishfinding.NewICMPScanner(input, output)

	var total int
	var alive int

	golog.Infof("start scanning")

	start := time.Now()
	// 将待探测的IP发送给send goroutine
	go func() {
		lines := fishfinding.ReadIPList("../../config/ipv4.txt")
		for _, line := range lines {
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
