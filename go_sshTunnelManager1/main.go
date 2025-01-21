package main

import (
    "bufio"
    "encoding/json"
    "flag"
    "fmt"
    "html/template"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "os/signal"
    "sort"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    socks5proxy "github.com/cloudfoundry/socks5-proxy"
    "golang.org/x/crypto/ssh"
)

// GlobalSettings holds the global configuration and state
type GlobalSettings struct {
    LogFile     string
    LogLevel    string
    Config      []SSHTunnelConfig
    Clients     map[string]*SSHClient
    ConfigPath  string
    WebHost     string
    WebPort     string
    StopChan    chan struct{}
    NoAutoStart bool
    Mutex       sync.Mutex
}

var globalSettings = &GlobalSettings{
    LogFile:  "ssh_tunnel_manager.log",
    LogLevel: "DEBUG",
    Clients:  make(map[string]*SSHClient),
    WebHost:  "127.0.0.1",
    WebPort:  "9988",
    StopChan: make(chan struct{}),
}

// SSHTunnelConfig represents the configuration for an SSH tunnel
type SSHTunnelConfig struct {
    Name           string   `json:"name"`
    Host           string   `json:"host"`
    Port           int      `json:"port"`
    Username       string   `json:"username"`
    Password       string   `json:"password"`
    LocalPort      int      `json:"local_port"`
    Group          string   `json:"group"`
    Comment        string   `json:"comment"`
    SSHOptions     []string `json:"ssh_options"`
    SerialNumber   int      `json:"serial_number"`
    MaxReconnects  int      `json:"max_reconnects"`
    AutoReconnects int      `json:"auto_reconnects"`
}

// SSHClient manages an individual SSH tunnel and its SOCKS5 proxy
type SSHClient struct {
    Config            SSHTunnelConfig
    Status            string
    StopChan          chan struct{}
    StopOnce          sync.Once
    ReconnectAttempts int
    Mutex             sync.Mutex
    LogFile           *os.File

    // SSH related fields
    sshClient *ssh.Client
    proxy     *socks5proxy.Socks5Proxy
}

// Template functions
var funcMap = template.FuncMap{
    "add": func(a, b int) int {
        return a + b
    },
    "capitalize": func(s string) string {
        if len(s) == 0 {
            return s
        }
        return strings.ToUpper(s[:1]) + s[1:]
    },
    "safeID": func(s string) string {
        s = strings.ToLower(s)
        s = strings.ReplaceAll(s, " ", "_")
        s = strings.ReplaceAll(s, "/", "_")
        s = strings.ReplaceAll(s, "\\", "_")
        // Remove special characters
        s = strings.Map(func(r rune) rune {
            if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
                return r
            }
            return -1
        }, s)
        return s
    },
}

var tmpl *template.Template

func main() {
    defer func() {
        if r := recover(); r != nil {
            logError("Application panicked: %v", r)
            cleanup()
            os.Exit(1)
        }
    }()

    parseArguments()
    setupLogging()
    logInfo("SSH Tunnel Manager starting...")
    loadConfig(globalSettings.ConfigPath)
    initClients()
    setupSignalHandlers()
    go monitorClients()

    var err error
    tmpl, err = template.New("index.html").Funcs(funcMap).ParseFiles("templates/index.html")
    if err != nil {
        log.Fatalf("Error parsing template: %v", err)
    }

    startWebServer()
}

// parseArguments parses command-line arguments and updates global settings
func parseArguments() {
    var (
        showHelp    bool
        configPath  string
        logLevel    string
        webHost     string
        webPort     string
        noAutoStart bool
    )

    flag.BoolVar(&showHelp, "h", false, "Show help message")
    flag.BoolVar(&showHelp, "help", false, "Show help message")
    flag.StringVar(&configPath, "c", "", "Path to JSON configuration file")
    flag.StringVar(&configPath, "config", "", "Path to JSON configuration file")
    flag.StringVar(&logLevel, "log-level", "DEBUG", "Set logging level (DEBUG, INFO, WARNING, ERROR)")
    flag.StringVar(&webHost, "web-host", "127.0.0.1", "Host for the web interface")
    flag.StringVar(&webPort, "web-port", "9966", "Port for the web interface")
    flag.BoolVar(&noAutoStart, "no-auto-connect", false, "Disable auto connection of SSH tunnels on startup")
    flag.Parse()

    if showHelp {
        fmt.Println("Usage:")
        fmt.Println("  ssh_tunnel_manager -c config.json [options]")
        fmt.Println("")
        fmt.Println("Options:")
        fmt.Println("  -c, --config        Path to JSON configuration file (required)")
        fmt.Println("  --log-level         Set logging level (DEBUG, INFO, WARNING, ERROR) (default: INFO)")
        fmt.Println("  --web-host          Host for the web interface (default: 127.0.0.1)")
        fmt.Println("  --web-port          Port for the web interface (default: 9966)")
        fmt.Println("  --no-auto-connect   Disable auto connection of SSH tunnels on startup")
        fmt.Println("  -h, --help          Show help message")
        os.Exit(0)
    }

    if configPath == "" {
        logError("Configuration file is required. Use -c config.json")
        os.Exit(1)
    }

    globalSettings.ConfigPath = configPath
    globalSettings.LogLevel = strings.ToUpper(logLevel)
    globalSettings.WebHost = webHost
    globalSettings.WebPort = webPort
    globalSettings.NoAutoStart = noAutoStart
}

// setupLogging configures the logging to write to both stdout and a log file
func setupLogging() {
    logFile, err := os.OpenFile(globalSettings.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }

    mw := io.MultiWriter(os.Stdout, logFile)
    log.SetOutput(mw)
    log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
}

// loadConfig reads and parses the JSON configuration file
func loadConfig(configPath string) {
    data, err := os.ReadFile(configPath)
    if err != nil {
        logError("Failed to read config file: %v", err)
        os.Exit(1)
    }

    var config []SSHTunnelConfig
    if err := json.Unmarshal(data, &config); err != nil {
        logError("Config file is not valid JSON: %v", err)
        os.Exit(1)
    }

    validateConfig(config)
    globalSettings.Config = config
}

// validateConfig ensures that each SSH tunnel configuration has the required fields
func validateConfig(config []SSHTunnelConfig) {
    for idx, sshConfig := range config {
        if sshConfig.Name == "" || sshConfig.Host == "" || sshConfig.Username == "" || sshConfig.LocalPort == 0 {
            logError("Invalid configuration at index %d: missing required fields.", idx)
            os.Exit(1)
        }
    }
}

// initClients initializes SSH clients based on the loaded configuration
func initClients() {
    for idx, sshConfig := range globalSettings.Config {
        sshConfig.SerialNumber = idx + 1
        client := &SSHClient{
            Config:   sshConfig,
            Status:   "stopped",
            StopChan: make(chan struct{}),
        }
        globalSettings.Clients[sshConfig.Name] = client

        if !globalSettings.NoAutoStart {
            go client.Start()
        }
    }
}

// Start initiates the SSH connection and starts the SOCKS5 proxy
func (client *SSHClient) Start() {
    client.Mutex.Lock()
    if client.Status == "running" || client.Status == "connecting" {
        client.Mutex.Unlock()
        logWarning("SSH tunnel '%s' is already running or connecting.", client.Config.Name)
        return
    }
    client.Status = "connecting"
    client.Mutex.Unlock()

    client.ReconnectAttempts = 0
    client.StopChan = make(chan struct{})
    client.StopOnce = sync.Once{}

    go client.run()
}

// run manages the SSH connection and SOCKS5 proxy lifecycle with auto-reconnect
func (client *SSHClient) run() {
    for {
        select {
        case <-client.StopChan:
            client.cleanup()
            return
        default:
            err := client.startProxy()
            if err != nil {
                logError("Failed to start proxy for tunnel '%s': %v", client.Config.Name, err)
                client.setStatus("error")
            }

            // Wait until the proxy stops or a stop signal is received
            select {
            case <-client.StopChan:
                client.cleanup()
                return
            case <-time.After(time.Second):
                // Continue to check the status
            }

            // Check if reconnection is needed
            if client.Config.AutoReconnects > 0 && client.ReconnectAttempts < client.Config.MaxReconnects {
                client.ReconnectAttempts++
                logWarning("SSH tunnel '%s' disconnected. Reconnecting... (%d/%d)", client.Config.Name, client.ReconnectAttempts, client.Config.MaxReconnects)
                time.Sleep(5 * time.Second)
            } else {
                client.setStatus("stopped")
                return
            }
        }
    }
}

// startProxy establishes the SSH connection and starts the SOCKS5 proxy
func (client *SSHClient) startProxy() error {
    client.setStatus("connecting")

    sshConfig := &ssh.ClientConfig{
        User:            client.Config.Username,
        Auth:            []ssh.AuthMethod{},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(), // ⚠️ Insecure, consider using a proper HostKeyCallback
        Timeout:         5 * time.Second,
        Config: ssh.Config{
            KeyExchanges: []string{
                "diffie-hellman-group1-sha1",
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1",
                "diffie-hellman-group-exchange-sha256",
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "diffie-hellman-group14-sha256",
                "curve25519-sha256@libssh.org",
            },
            Ciphers: []string{
                "aes128-cbc",
                "aes192-cbc",
                "aes256-cbc",
                "3des-cbc",
                "aes128-ctr",
                "aes192-ctr",
                "aes256-ctr",
                "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com",
            },
            MACs: []string{
                "hmac-sha1",
                "hmac-sha2-256",
                "hmac-sha2-512",
                "umac-64@openssh.com",
                "umac-128@openssh.com",
            },
        },
    }

    // Add password authentication if provided
    if client.Config.Password != "" {
        sshConfig.Auth = append(sshConfig.Auth, ssh.Password(client.Config.Password))
    }

    // Establish SSH connection
    sshAddress := fmt.Sprintf("%s:%d", client.Config.Host, client.Config.Port)
    logInfo("Establishing SSH connection for tunnel '%s' to %s...", client.Config.Name, sshAddress)
    client.sshClient, err := ssh.Dial("tcp", sshAddress, sshConfig)
    if err != nil {
        logError("Failed to establish SSH connection for tunnel '%s': %v", client.Config.Name, err)
        client.setStatus("error")
        return err
    }
    logInfo("SSH connection established for tunnel '%s'.", client.Config.Name)

    // Set up keep-alive
    go client.keepAlive()

    // Initialize SOCKS5 proxy
    client.proxy = socks5proxy.NewSocks5Proxy(socks5proxy.NewHostKey(), log.New(os.Stdout, fmt.Sprintf("socks5-proxy [%s]: ", client.Config.Name), log.LstdFlags), 30*time.Second)

    // Set SOCKS5 proxy listen port
    client.proxy.SetListenPort(client.Config.LocalPort)
    logInfo("Starting SOCKS5 proxy for tunnel '%s' on port %d...", client.Config.Name, client.Config.LocalPort)

    // Define custom dialer using SSH client
    dialFunc := func(network, address string) (net.Conn, error) {
        return client.sshClient.Dial(network, address)
    }

    // Start the SOCKS5 proxy
    go func() {
        err := client.proxy.StartWithDialer(dialFunc)
        if err != nil {
            logError("SOCKS5 proxy for tunnel '%s' stopped with error: %v", client.Config.Name, err)
            client.setStatus("error")
            client.Stop()
        }
    }()

    client.setStatus("running")
    return nil
}

// keepAlive sends periodic keep-alive messages to maintain the SSH connection
func (client *SSHClient) keepAlive() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-client.StopChan:
            return
        case <-ticker.C:
            if client.sshClient == nil {
                continue
            }
            _, _, err := client.sshClient.SendRequest("keepalive@ssh_tunnel_manager", true, nil)
            if err != nil {
                logWarning("Keep-alive failed for tunnel '%s': %v", client.Config.Name, err)
                client.Stop()
                return
            }
            logDebug("Keep-alive sent for tunnel '%s'.", client.Config.Name)
        }
    }
}

// Stop terminates the SSH connection and stops the SOCKS5 proxy
func (client *SSHClient) Stop() {
    client.Mutex.Lock()
    if client.Status != "running" && client.Status != "connecting" {
        client.Mutex.Unlock()
        return
    }
    client.Status = "stopped"
    client.Mutex.Unlock()
    client.StopOnce.Do(func() {
        close(client.StopChan)
    })
    client.cleanup()
}

// cleanup closes the SSH connection and stops the SOCKS5 proxy
func (client *SSHClient) cleanup() {
    if client.proxy != nil {
        logInfo("Stopping SOCKS5 proxy for tunnel '%s'...", client.Config.Name)
        client.proxy.Stop()
        client.proxy = nil
    }

    if client.sshClient != nil {
        logInfo("Closing SSH connection for tunnel '%s'...", client.Config.Name)
        err := client.sshClient.Close()
        if err != nil {
            logError("Error closing SSH connection for tunnel '%s': %v", client.Config.Name, err)
        } else {
            logInfo("SSH connection closed for tunnel '%s'.", client.Config.Name)
        }
        client.sshClient = nil
    }
}

// Restart stops and then starts the SSH tunnel
func (client *SSHClient) Restart() {
    logInfo("Restarting SSH tunnel '%s'...", client.Config.Name)
    client.Stop()
    time.Sleep(2 * time.Second) // Brief pause before restarting
    client.Start()
}

// setStatus safely updates the tunnel status
func (client *SSHClient) setStatus(status string) {
    client.Mutex.Lock()
    client.Status = status
    client.Mutex.Unlock()
}

// monitorClients periodically checks the status of all clients and attempts reconnections
func monitorClients() {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            for _, client := range globalSettings.Clients {
                client.Mutex.Lock()
                status := client.Status
                client.Mutex.Unlock()
                if status != "running" && client.Config.AutoReconnects > 0 && client.ReconnectAttempts < client.Config.MaxReconnects {
                    go client.Start()
                }
            }
        case <-globalSettings.StopChan:
            return
        }
    }
}

// setupSignalHandlers handles OS signals for graceful shutdown
func setupSignalHandlers() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        sig := <-c
        logInfo("Received signal: %v", sig)
        cleanup()
        os.Exit(0)
    }()
}

// cleanup stops all SSH clients and performs necessary cleanup
func cleanup() {
    close(globalSettings.StopChan)
    stopAllClients()
    logInfo("SSH Tunnel Manager stopped.")
}

// stopAllClients stops all active SSH clients
func stopAllClients() {
    for _, client := range globalSettings.Clients {
        client.Stop()
    }
}

// startWebServer initializes and starts the HTTP web server
func startWebServer() {
    defer func() {
        if r := recover(); r != nil {
            logError("Web server panicked: %v", r)
        }
    }()

    http.HandleFunc("/", indexHandler)
    http.HandleFunc("/start", startTunnelHandler)
    http.HandleFunc("/stop", stopTunnelHandler)
    http.HandleFunc("/restart", restartTunnelHandler)
    http.HandleFunc("/add", addTunnelHandler)
    http.HandleFunc("/edit", editTunnelHandler)
    http.HandleFunc("/edit_global", editGlobalHandler)
    http.HandleFunc("/delete", deleteTunnelHandler)
    http.HandleFunc("/logs", logsHandler)
    http.HandleFunc("/toggle_theme", toggleThemeHandler)
    http.HandleFunc("/bulk_action", bulkActionHandler)

    addr := globalSettings.WebHost + ":" + globalSettings.WebPort
    logInfo("Starting web server at %s...", addr)
    if err := http.ListenAndServe(addr, nil); err != nil {
        logError("Failed to start web server: %v", err)
        cleanup()
        os.Exit(1)
    }
}

// HTTP Handlers

// indexHandler serves the main dashboard
func indexHandler(w http.ResponseWriter, r *http.Request) {
    data := struct {
        Tunnels           []*SSHClient
        TotalTunnels      int
        ActiveTunnels     int
        ErrorTunnels      int
        RestartingTunnels int
        Theme             string
        GroupedTunnels    map[string][]*SSHClient
        Page              string
    }{
        Tunnels:           getTunnelList(),
        TotalTunnels:      len(globalSettings.Clients),
        ActiveTunnels:     getActiveTunnelCount(),
        ErrorTunnels:      getErrorTunnelCount(),
        RestartingTunnels: getRestartingTunnelCount(),
        Theme:             getThemeFromCookie(r),
        GroupedTunnels:    getGroupedTunnels(),
        Page:              "index",
    }

    if err := tmpl.Execute(w, data); err != nil {
        logError("Error executing template: %v", err)
    }
}

// startTunnelHandler handles requests to start a specific tunnel
func startTunnelHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tunnelName := r.FormValue("name")
    client, ok := globalSettings.Clients[tunnelName]
    if ok {
        logInfo("Starting tunnel '%s' via web interface", tunnelName)
        go client.Start()
    } else {
        logWarning("Tunnel '%s' not found", tunnelName)
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

// stopTunnelHandler handles requests to stop a specific tunnel
func stopTunnelHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tunnelName := r.FormValue("name")
    client, ok := globalSettings.Clients[tunnelName]
    if ok {
        logInfo("Stopping tunnel '%s' via web interface", tunnelName)
        client.Stop()
    } else {
        logWarning("Tunnel '%s' not found", tunnelName)
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

// restartTunnelHandler handles requests to restart a specific tunnel
func restartTunnelHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tunnelName := r.FormValue("name")
    client, ok := globalSettings.Clients[tunnelName]
    if ok {
        logInfo("Restarting tunnel '%s' via web interface", tunnelName)
        client.Restart()
    } else {
        logWarning("Tunnel '%s' not found", tunnelName)
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

// addTunnelHandler handles adding a new SSH tunnel
func addTunnelHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        data := struct {
            Theme string
            Page  string
        }{
            Theme: getThemeFromCookie(r),
            Page:  "add",
        }
        if err := tmpl.Execute(w, data); err != nil {
            logError("Error executing template: %v", err)
        }
    } else if r.Method == http.MethodPost {
        r.ParseForm()
        name := r.FormValue("name")
        host := r.FormValue("host")
        port, _ := strconv.Atoi(r.FormValue("port"))
        username := r.FormValue("username")
        password := r.FormValue("password")
        localPort, _ := strconv.Atoi(r.FormValue("local_port"))
        group := r.FormValue("group")
        comment := r.FormValue("comment")
        maxReconnects, _ := strconv.Atoi(r.FormValue("max_reconnects"))
        autoReconnects, _ := strconv.Atoi(r.FormValue("auto_reconnects"))

        serialNumber := len(globalSettings.Config) + 1

        sshConfig := SSHTunnelConfig{
            Name:           name,
            Host:           host,
            Port:           port,
            Username:       username,
            Password:       password,
            LocalPort:      localPort,
            Group:          group,
            Comment:        comment,
            SerialNumber:   serialNumber,
            MaxReconnects:  maxReconnects,
            AutoReconnects: autoReconnects,
            SSHOptions:     []string{},
        }

        globalSettings.Config = append(globalSettings.Config, sshConfig)
        saveConfig()

        client := &SSHClient{
            Config:   sshConfig,
            Status:   "stopped",
            StopChan: make(chan struct{}),
        }
        globalSettings.Clients[sshConfig.Name] = client

        logInfo("Added new tunnel '%s' via web interface", name)
        http.Redirect(w, r, "/", http.StatusFound)
    }
}

// editTunnelHandler handles editing an existing SSH tunnel
func editTunnelHandler(w http.ResponseWriter, r *http.Request) {
    tunnelName := r.URL.Query().Get("name")
    client, ok := globalSettings.Clients[tunnelName]
    if !ok {
        logWarning("Tunnel '%s' not found", tunnelName)
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }

    if r.Method == http.MethodGet {
        data := struct {
            Theme  string
            Page   string
            Tunnel *SSHClient
        }{
            Theme:  getThemeFromCookie(r),
            Page:   "edit",
            Tunnel: client,
        }
        if err := tmpl.Execute(w, data); err != nil {
            logError("Error executing template: %v", err)
        }
    } else if r.Method == http.MethodPost {
        r.ParseForm()
        oldName := client.Config.Name
        client.Config.Name = r.FormValue("name")
        client.Config.Host = r.FormValue("host")
        client.Config.Port, _ = strconv.Atoi(r.FormValue("port"))
        client.Config.Username = r.FormValue("username")
        client.Config.Password = r.FormValue("password")
        client.Config.LocalPort, _ = strconv.Atoi(r.FormValue("local_port"))
        client.Config.Group = r.FormValue("group")
        client.Config.Comment = r.FormValue("comment")
        client.Config.MaxReconnects, _ = strconv.Atoi(r.FormValue("max_reconnects"))
        client.Config.AutoReconnects, _ = strconv.Atoi(r.FormValue("auto_reconnects"))

        // Update configuration in globalSettings.Config
        for idx, cfg := range globalSettings.Config {
            if cfg.Name == oldName {
                globalSettings.Config[idx] = client.Config
                break
            }
        }
        // If the name has changed, update the Clients map
        if oldName != client.Config.Name {
            globalSettings.Clients[client.Config.Name] = client
            delete(globalSettings.Clients, oldName)
        }
        saveConfig()
        logInfo("Edited tunnel '%s' via web interface", tunnelName)
        http.Redirect(w, r, "/", http.StatusFound)
    }
}

// editGlobalHandler handles editing global settings
func editGlobalHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        data := struct {
            Theme string
            Page  string
        }{
            Theme: getThemeFromCookie(r),
            Page:  "edit_global",
        }
        if err := tmpl.Execute(w, data); err != nil {
            logError("Error executing template: %v", err)
        }
    } else if r.Method == http.MethodPost {
        r.ParseForm()
        maxReconnects, _ := strconv.Atoi(r.FormValue("max_reconnects"))
        for _, client := range globalSettings.Clients {
            client.Config.MaxReconnects = maxReconnects
        }
        // Update globalSettings.Config
        for idx := range globalSettings.Config {
            globalSettings.Config[idx].MaxReconnects = maxReconnects
        }
        saveConfig()
        logInfo("Updated global max reconnections to %d via web interface", maxReconnects)
        http.Redirect(w, r, "/", http.StatusFound)
    }
}

// deleteTunnelHandler handles deleting an existing SSH tunnel
func deleteTunnelHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tunnelName := r.FormValue("name")
    client, ok := globalSettings.Clients[tunnelName]
    if ok {
        logInfo("Deleting tunnel '%s' via web interface", tunnelName)
        client.Stop()
        delete(globalSettings.Clients, tunnelName)
        for i, cfg := range globalSettings.Config {
            if cfg.Name == tunnelName {
                globalSettings.Config = append(globalSettings.Config[:i], globalSettings.Config[i+1:]...)
                break
            }
        }
        saveConfig()
    } else {
        logWarning("Tunnel '%s' not found", tunnelName)
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

// logsHandler displays the latest logs
func logsHandler(w http.ResponseWriter, r *http.Request) {
    N := 100
    file, err := os.Open(globalSettings.LogFile)
    if err != nil {
        logError("Failed to read log file: %v", err)
        http.Error(w, "Failed to read log file", http.StatusInternalServerError)
        return
    }
    defer file.Close()

    lines := []string{}
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }

    if len(lines) > N {
        lines = lines[len(lines)-N:]
    }

    data := struct {
        Logs  []string
        Theme string
        Page  string
    }{
        Logs:  lines,
        Theme: getThemeFromCookie(r),
        Page:  "logs",
    }

    if err := tmpl.Execute(w, data); err != nil {
        logError("Error executing template: %v", err)
    }
}

// toggleThemeHandler toggles the UI theme between light and dark
func toggleThemeHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    theme := r.FormValue("theme")
    if theme == "" {
        theme = "light"
    }
    cookie := &http.Cookie{
        Name:    "theme",
        Value:   theme,
        Expires: time.Now().Add(365 * 24 * time.Hour),
    }
    http.SetCookie(w, cookie)
    logInfo("Theme changed to '%s' via web interface", theme)
    http.Redirect(w, r, "/", http.StatusFound)
}

// bulkActionHandler handles bulk actions on selected tunnels
func bulkActionHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    err := r.ParseForm()
    if err != nil {
        logError("Error parsing form data: %v", err)
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    action := r.FormValue("action")
    selectedTunnels := r.Form["selected_tunnels"]
    if action == "" {
        logWarning("Action not specified in bulk action")
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    if len(selectedTunnels) == 0 {
        logWarning("No tunnels selected for bulk action '%s'", action)
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    for _, tunnelName := range selectedTunnels {
        client, ok := globalSettings.Clients[tunnelName]
        if ok {
            switch action {
            case "start_selected":
                logInfo("Starting selected tunnel '%s' via web interface", tunnelName)
                go client.Start()
            case "stop_selected":
                logInfo("Stopping selected tunnel '%s' via web interface", tunnelName)
                client.Stop()
            case "restart_selected":
                logInfo("Restarting selected tunnel '%s' via web interface", tunnelName)
                client.Restart()
            case "delete_selected":
                logInfo("Deleting selected tunnel '%s' via web interface", tunnelName)
                client.Stop()
                delete(globalSettings.Clients, tunnelName)
                for i, cfg := range globalSettings.Config {
                    if cfg.Name == tunnelName {
                        globalSettings.Config = append(globalSettings.Config[:i], globalSettings.Config[i+1:]...)
                        break
                    }
                }
                saveConfig()
            default:
                logWarning("Unknown bulk action: %s", action)
            }
        } else {
            logWarning("Selected tunnel '%s' not found", tunnelName)
        }
    }
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Helper Functions

// getTunnelList returns a sorted list of SSH clients
func getTunnelList() []*SSHClient {
    tunnels := []*SSHClient{}
    for _, client := range globalSettings.Clients {
        tunnels = append(tunnels, client)
    }

    sort.Slice(tunnels, func(i, j int) bool {
        return tunnels[i].Config.SerialNumber < tunnels[j].Config.SerialNumber
    })

    return tunnels
}

// getActiveTunnelCount returns the number of active tunnels
func getActiveTunnelCount() int {
    count := 0
    for _, client := range globalSettings.Clients {
        client.Mutex.Lock()
        if client.Status == "running" {
            count++
        }
        client.Mutex.Unlock()
    }
    return count
}

// getErrorTunnelCount returns the number of tunnels in error state
func getErrorTunnelCount() int {
    count := 0
    for _, client := range globalSettings.Clients {
        client.Mutex.Lock()
        if client.Status == "error" {
            count++
        }
        client.Mutex.Unlock()
    }
    return count
}

// getRestartingTunnelCount returns the number of tunnels currently restarting
func getRestartingTunnelCount() int {
    count := 0
    for _, client := range globalSettings.Clients {
        client.Mutex.Lock()
        if client.Status == "restarting" {
            count++
        }
        client.Mutex.Unlock()
    }
    return count
}

// getGroupedTunnels groups tunnels by their group names
func getGroupedTunnels() map[string][]*SSHClient {
    grouped := make(map[string][]*SSHClient)
    for _, client := range globalSettings.Clients {
        group := client.Config.Group
        if group == "" {
            group = "Default"
        }
        grouped[group] = append(grouped[group], client)
    }

    // Sort groups
    sortedGroups := make(map[string][]*SSHClient)
    groupNames := make([]string, 0, len(grouped))
    for group := range grouped {
        groupNames = append(groupNames, group)
    }
    sort.Strings(groupNames)
    for _, group := range groupNames {
        tunnels := grouped[group]
        // Sort tunnels within the group by SerialNumber
        sort.Slice(tunnels, func(i, j int) bool {
            return tunnels[i].Config.SerialNumber < tunnels[j].Config.SerialNumber
        })
        sortedGroups[group] = tunnels
    }

    return sortedGroups
}

// getThemeFromCookie retrieves the UI theme from cookies
func getThemeFromCookie(r *http.Request) string {
    cookie, err := r.Cookie("theme")
    if err != nil {
        return "light"
    }
    return cookie.Value
}

// saveConfig writes the current configuration back to the JSON file
func saveConfig() {
    data, err := json.MarshalIndent(globalSettings.Config, "", "  ")
    if err != nil {
        logError("Error saving configuration: %v", err)
        return
    }

    err = os.WriteFile(globalSettings.ConfigPath, data, 0644)
    if err != nil {
        logError("Error writing config file: %v", err)
    } else {
        logInfo("Configuration saved to '%s'", globalSettings.ConfigPath)
    }
}

// Logging Functions

// logWithLevel logs messages with the specified level and appropriate formatting
func logWithLevel(level string, format string, v ...interface{}) {
    message := fmt.Sprintf(format, v...)
    timestamp := time.Now().Format("2006-01-02 15:04:05.000")
    switch strings.ToUpper(level) {
    case "DEBUG":
        if globalSettings.LogLevel == "DEBUG" {
            log.Printf("%s - DEBUG - %s", timestamp, message)
        }
    case "INFO":
        if globalSettings.LogLevel == "DEBUG" || globalSettings.LogLevel == "INFO" {
            log.Printf("%s - INFO - %s", timestamp, message)
        }
    case "WARNING":
        if globalSettings.LogLevel == "DEBUG" || globalSettings.LogLevel == "INFO" || globalSettings.LogLevel == "WARNING" {
            log.Printf("%s - WARNING - %s", timestamp, message)
        }
    case "ERROR":
        log.Printf("%s - ERROR - %s", timestamp, message)
    default:
        fmt.Printf("%s - %s - %s\n", timestamp, level, message)
        log.Printf("%s - %s", level, message)
    }
}

// logDebug logs debug-level messages
func logDebug(format string, v ...interface{}) {
    logWithLevel("DEBUG", format, v...)
}

// logInfo logs info-level messages
func logInfo(format string, v ...interface{}) {
    logWithLevel("INFO", format, v...)
}

// logWarning logs warning-level messages
func logWarning(format string, v ...interface{}) {
    logWithLevel("WARNING", format, v...)
}

// logError logs error-level messages
func logError(format string, v ...interface{}) {
    logWithLevel("ERROR", format, v...)
}
