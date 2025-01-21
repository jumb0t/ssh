package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"github.com/spf13/pflag"
	"github.com/pkg/errors"
)

type Config struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	LocalPort    int      `json:"local_port"`
	Group        string   `json:"group"`
	Comment      string   `json:"comment"`
	SshOptions   []string `json:"ssh_options"`
	SerialNumber int      `json:"serial_number"`
	MaxReconnects int     `json:"max_reconnects"`
	AutoReconnects int    `json:"auto_reconnects"`
}

func sshConnectWithSOCKS5(proxyPort int, config Config, timeout time.Duration) error {
	log.Printf("Starting SSH connection to %s:%d with username %s\n", config.Host, config.Port, config.Username)

	// Set timeout for the connection
	clientConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout, // Set timeout for the connection
	}

	// Attempt SSH connection
	log.Printf("Attempting to connect to SSH server %s:%d\n", config.Host, config.Port)
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.Host, config.Port), clientConfig)
	if err != nil {
		return fmt.Errorf("error connecting to SSH server: %v", err)
	}
	defer client.Close()
	log.Printf("Successfully connected to SSH server %s:%d\n", config.Host, config.Port)

	// Set up a SOCKS5 proxy
	log.Printf("Setting up SOCKS5 proxy on local port %d\n", proxyPort)
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", proxyPort))
	if err != nil {
		return fmt.Errorf("could not bind to local port %d: %v", proxyPort, err)
	}
	defer listener.Close()

	// Handle incoming connections and tunnel them over SSH
	go handleConnections(listener, client)

	// Keep the SSH session alive
	go keepSSHAlive(client)

	// Wait for shutdown or interruption
	select {}
}

func handleConnections(listener net.Listener, client *ssh.Client) {
	log.Printf("Started listening for incoming connections...\n")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		log.Printf("Accepted new connection from %s\n", conn.RemoteAddr())
		go tunnelTraffic(conn, client)
	}
}

func tunnelTraffic(localConn net.Conn, client *ssh.Client) {
	defer localConn.Close()
	log.Printf("Starting tunnel between local connection %s and SSH server\n", localConn.RemoteAddr())

	// Establish a new session
	session, err := client.NewSession()
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		return
	}
	defer session.Close()

	// Set up the input/output pipes
	remoteConn, err := session.StdoutPipe()
	if err != nil {
		log.Printf("Failed to create remote connection: %v", err)
		return
	}

	// Now we have to make sure to send and receive data
	// First, copy data from localConn to remoteConn (SSH server)
	go transferData(localConn, remoteConn)
	// Then, copy data from remoteConn (SSH server) to localConn
	go transferData(remoteConn, localConn)
}

func transferData(src io.Reader, dst io.Writer) {
	log.Printf("Starting data transfer between %v and %v\n", src, dst)
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Printf("Data transfer error: %v", err)
	}
	log.Printf("Data transfer complete\n")
}

func keepSSHAlive(client *ssh.Client) {
	log.Printf("Started sending keepalive messages to SSH server...\n")
	for {
		_, _, err := client.SendRequest("keepalive", true, nil) // Handling 3 return values (ignore the third one)
		if err != nil {
			log.Printf("SSH keepalive error: %v", err)
			return
		}
		time.Sleep(1 * time.Second)
	}
}

func loadConfig(file string) ([]Config, error) {
	log.Printf("Loading configuration file: %s\n", file)
	var configs []Config
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read config file")
	}
	err = json.Unmarshal(data, &configs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal config file")
	}
	log.Printf("Successfully loaded configuration\n")
	return configs, nil
}

func parseCIDR(file string) ([]string, error) {
	log.Printf("Parsing CIDR from file: %s\n", file)
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
		if strings.Contains(line, "/") {
			_, network, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR format: %v", err)
			}
			for ip := network.IP; network.Contains(ip); incrementIP(ip) {
				ipList = append(ipList, ip.String())
			}
		} else {
			ipList = append(ipList, line)
		}
	}
	log.Printf("Parsed %d IP addresses from CIDR\n", len(ipList))
	return ipList, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func main() {
	// Parsing command-line arguments
	var threads int
	var timeout int
	var configFile string
	var debug bool

	pflag.IntVar(&threads, "threads", 10, "Number of concurrent threads")
	pflag.IntVar(&timeout, "timeout", 5, "Connection timeout in seconds")
	pflag.StringVar(&configFile, "config", "", "JSON configuration file")
	pflag.BoolVar(&debug, "debug", false, "Enable debug mode")
	pflag.Parse()

	// Setup timeout
	timeoutDuration := time.Duration(timeout) * time.Second

	if configFile != "" {
		// Load configuration from the JSON file
		configs, err := loadConfig(configFile)
		if err != nil {
			log.Fatalf("Error loading config file: %v", err)
		}

		var wg sync.WaitGroup
		for _, config := range configs {
			// Check if the local port is available
			listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", config.LocalPort))
			if err != nil {
				log.Printf("Port %d is already in use, skipping configuration %s", config.LocalPort, config.Name)
				continue
			}
			listener.Close() // Close the listener if port is free

			wg.Add(1)
			go func(config Config) {
				defer wg.Done()
				err := sshConnectWithSOCKS5(config.LocalPort, config, timeoutDuration)
				if err != nil {
					log.Printf("Error with SSH connection for %s: %v", config.Name, err)
				}
			}(config)
		}
		wg.Wait()
	}
}
