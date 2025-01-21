package main

import (
	"net"
	"os"
	"strings"
	"time"

	"github.com/kataras/golog"
	"golang.org/x/net/bpf"
)

func readIPList() []string {
	golog.Info("reading ipv4.txt")
	data, err := os.ReadFile("ipv4.txt")
	if err != nil {
		golog.Fatal(err)
	}

	golog.Info("splitting the IPs")
	return strings.Split(string(data), "\n")
}

func getLocalIP() string {

	conn, err := net.DialTimeout("udp", "114.114.114.114", 10*time.Second)
	if err != nil {
		golog.Fatalf("failed to get local IP address: %v", err)
	}
	localIP := conn.LocalAddr().String()
	conn.Close()

	host, _, _ := net.SplitHostPort(localIP)

	return host
}

func cidr2IPList(cidr string) []string {
	var ips []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		golog.Fatal(err)
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ip = incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

func incIP(ip net.IP) net.IP {
	return int2IP(ip2Int(ip) + 1)
}

func ip2Int(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])
}

func int2IP(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(ipInt >> 24)
	ip[1] = byte(ipInt >> 16)
	ip[2] = byte(ipInt >> 8)
	ip[3] = byte(ipInt)
	return ip
}

type Filter []bpf.Instruction

func createEmptyFilter() Filter {
	filter := Filter{
		bpf.RetConstant{Val: 0x0},
	}
	return filter
}
