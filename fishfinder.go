package main

import (
	"flag"
	"runtime"
	"sync"
	"time"

	"github.com/kataras/golog"
)

var (
	protocol    = flag.String("p", "icmp", "The protocol to use (icmp, tcp or udp)")
	concurrency = flag.Int("c", runtime.NumCPU(), "The concurrency to send")
)

// 嵌入ip.sh

func main() {
	flag.Parse()

	var wg sync.WaitGroup
	wg.Add(*concurrency)
	scanner := NewICMPScanner(getLocalIP(), *concurrency, &wg)

	var total int
	var alive int
	start := time.Now()
	golog.Infof("start scanning")

	input := make(chan []string, 1024)
	// 将待探测的IP发送给send goroutine
	go func() {
		lines := readIPList()
		for _, line := range lines {
			ips := cidr2IPList(line)
			input <- ips
			total += len(ips)
		}
		close(input)
	}()

	// 启动 send goroutine
	output := scanner.Scan(input)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		time.Sleep(5 * time.Second)
		close(done)
	}()

	// 接收 send goroutine 发送的结果, 直到发送之后5秒结束
recv:
	for {
		select {
		case <-done:
			break recv
		case ip := <-output:
			golog.Infof("%s is alive", ip)
			alive++
		}
	}

	golog.Infof("total: %d, alive: %d, time: %v", total, alive, time.Since(start))
}
