package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v2"
)

var wg sync.WaitGroup

// Get the local IP address of the machine running the script
func getLocalIP() string {
	conn, err := net.Dial("udp", "192.255.255.255:1")
	if err != nil {
		fmt.Println(err)
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String()
}

// Scan the subnet for live hosts using nmap
func scanSubnet(ipRange string) []string {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ipRange),
		nmap.WithPingScan(),
	)
	if err != nil {
		fmt.Printf("unable to create nmap scanner: %v", err)
		os.Exit(1)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		fmt.Printf("unable to run nmap scan: %v", err)
		os.Exit(1)
	}

	if len(warnings) > 0 {
		fmt.Printf("Warnings: \n %v", warnings)
	}

	var liveHosts []string
	for _, host := range result.Hosts {
		if host.Status.State == "up" {
			liveHosts = append(liveHosts, host.Addresses[0].String())
		}
	}
	return liveHosts
}

// Check if a specific port is open
func isPortOpen(host string, port int, wg *sync.WaitGroup) {
	defer wg.Done()
	timeout := time.Second
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return
	}
	conn.Close()
	fmt.Printf("Port %d is open on %s\n", port, host)
}

func main() {
	localIP := getLocalIP()
	fmt.Println("Local IP: ", localIP)

	subnet := strings.Join(strings.Split(localIP, ".")[:3], ".") + ".0/24"
	fmt.Println("Subnet: ", subnet)

	liveHosts := scanSubnet(subnet)
	fmt.Println("Live hosts on subnet: ", liveHosts)

	ports := []int{22, 3389, 53, 80, 443, 21, 8080, 8081}

	for _, host := range liveHosts {
		for _, port := range ports {
			wg.Add(1)
			go isPortOpen(host, port, &wg)
		}
	}

	wg.Wait()
}
