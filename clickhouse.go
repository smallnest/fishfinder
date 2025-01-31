package fishfinding

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/kataras/golog"
)

type ClickHouseChecker struct {
	wg   *sync.WaitGroup
	port int

	input  chan string
	output chan string
}

func NewClickHouseChecker(port int, input chan string, output chan string, wg *sync.WaitGroup) *ClickHouseChecker {
	s := &ClickHouseChecker{
		port:   port,
		input:  input,
		output: output,
		wg:     wg,
	}
	return s
}

func (s *ClickHouseChecker) Check() {
	parallel := runtime.NumCPU()

	for i := 0; i < parallel; i++ {
		s.wg.Add(1)
		go s.check()
	}
}

func (s *ClickHouseChecker) check() {
	defer s.wg.Done()

	for ip := range s.input {
		if ip == "splitting" || ip == "failed" {
			continue
		}

		if isClickHouse(ip, s.port) {
			s.output <- ip
		}
	}
}

func isClickHouse(ip string, port int) bool {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", ip, port)},
		// Auth: clickhouse.Auth{
		// 	Database: "default",
		// 	Username: "default",
		// 	Password: "",
		// },
		Settings: clickhouse.Settings{
			"max_execution_time": 1,
		},
		DialTimeout:          time.Second,
		MaxOpenConns:         1,
		MaxIdleConns:         1,
		ConnMaxLifetime:      time.Duration(1) * time.Minute,
		ConnOpenStrategy:     clickhouse.ConnOpenInOrder,
		BlockBufferSize:      10,
		MaxCompressionBuffer: 1024,
	})
	if err != nil {
		golog.Errorf("open %s:%d failed: %v", ip, port, err)
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = conn.Ping(ctx)
	if err != nil {
		golog.Warnf("failed to connect %s:%d: %v", ip, port, err)
		return false
	}

	return true
}
