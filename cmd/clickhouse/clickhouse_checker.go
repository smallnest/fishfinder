package main

import (
	"flag"
	"strings"
	"sync"
	"time"

	"github.com/kataras/golog"
	"github.com/smallnest/fishfinding"
)

var (
	dstPort = flag.Int("d", 9000, "The destination port to use")
)

// 嵌入ip.sh

func main() {
	flag.Parse()

	input := make(chan string, 1024)
	output := make(chan string, 1024)
	var wg sync.WaitGroup
	checker := fishfinding.NewClickHouseChecker(*dstPort, input, output, &wg) // 改用 TCP 扫描器
	checker.Check()

	golog.Infof("start to check")

	start := time.Now()
	// 将待探测的IP发送给send goroutine
	go func() {
		lines := fishfinding.ReadAvailableIPList("../../config/port9000.txt")
		for _, line := range lines {
			// [INFO] 2025/01/26 20:58 1.27.222.121 is alive
			items := strings.Fields(line)
			if len(items) < 6 {
				continue
			}
			line := items[3]

			input <- line
		}
		close(input)
	}()

	total := 0
	go func() {
		// 接收 checker 的结果, 直到发送之后5秒结束
		for ip := range output {
			golog.Infof("%s can be accessed", ip)
			total++
		}
	}()

	wg.Wait()
	time.Sleep(time.Second)

	golog.Infof("total: %d, time: %v", total, time.Since(start))
}
