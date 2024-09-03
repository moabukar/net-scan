package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Ullaakut/nmap/v2"
)

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

// Perform a basic scan of the subnet for open ports
func scanSubnet(ipRange string) ([]nmap.Host, error) {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ipRange),
		nmap.WithPorts("1-1000"),     // Scan ports 1-1000
		nmap.WithSkipHostDiscovery(), // Skip host discovery to focus on port scanning
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %v", err)
	}

	if len(warnings) > 0 {
		fmt.Printf("Warnings: \n%v\n", warnings)
	}

	return result.Hosts, nil
}

func printScanResults(hosts []nmap.Host) {
	for _, host := range hosts {
		fmt.Printf("Host %s is up with the following details:\n", host.Addresses[0])
		if len(host.Ports) == 0 {
			fmt.Println("\tNo open ports found")
		}
		for _, port := range host.Ports {
			if port.State.State == "open" {
				fmt.Printf("\tPort %d (%s) is open\n", port.ID, port.Protocol)
			}
		}
		fmt.Println()
	}
}

func main() {
	localIP := getLocalIP()
	fmt.Println("Local IP: ", localIP)

	subnet := strings.Join(strings.Split(localIP, ".")[:3], ".") + ".0/24"
	fmt.Println("Subnet: ", subnet)

	hosts, err := scanSubnet(subnet)
	if err != nil {
		fmt.Printf("Error scanning subnet: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d live hosts\n", len(hosts))
	printScanResults(hosts)
}
