# SOCKS5 Proxy over SSH in C++

## Introduction

This project implements a SOCKS5 proxy server in C++ that forwards client connections over an SSH tunnel to target servers. It allows clients to connect to any server via the SOCKS5 protocol, with the proxy securely forwarding the traffic through an SSH connection.

The implementation uses `Boost.Asio` for asynchronous networking and `libssh` for SSH connections. It supports multiple clients simultaneously, handles the SOCKS5 protocol, and manages SSH sessions and channels efficiently.

## Features

- **SOCKS5 Proxy Server**: Implements the SOCKS5 protocol, supporting the `CONNECT` command.
- **SSH Tunneling**: Forwards client connections securely over SSH to target servers.
- **Asynchronous I/O**: Utilizes `Boost.Asio` for non-blocking network operations.
- **Thread-safe Logging**: Provides synchronized logging across multiple threads.
- **SSH Session Management**: Handles SSH connections, including reconnection logic.
- **IPv4 and Domain Name Support**: Supports both IPv4 addresses and domain names in SOCKS5 requests.
- **Customizable SSH Options**: Allows configuration of SSH parameters like ciphers, key exchange algorithms, and more.
- **Configurable Thread Pool**: Adjusts the number of threads handling client connections.

## Dependencies

- **Boost C++ Libraries** (specifically Boost.Asio)
  - Website: [https://www.boost.org/](https://www.boost.org/)
- **libssh**
  - Website: [https://www.libssh.org/](https://www.libssh.org/)
- **C++11 or Later**: Requires a modern C++ compiler supporting at least the C++11 standard.

## Compilation

To compile the code, ensure that both Boost and libssh are installed on your system. You can use `g++` or `clang++` to compile the code.

### Compilation Command

```bash
g++ -std=c++11 -o socks5_proxy ss.cpp -lboost_system -lboost_thread -lpthread -lssh
```

**Explanation:**

- `-std=c++11`: Use the C++11 standard.
- `-o socks5_proxy`: Name of the output executable.
- `ss.cpp`: Source code file.
- `-lboost_system -lboost_thread`: Link against Boost.System and Boost.Thread libraries.
- `-lpthread`: Link against the POSIX thread library.
- `-lssh`: Link against the libssh library.

**Note:** You might need to specify include paths and library paths if the libraries are not in standard locations:

```bash
g++ -std=c++11 -I/path/to/boost/include -I/path/to/libssh/include \
    -L/path/to/boost/lib -L/path/to/libssh/lib \
    -o socks5_proxy ss.cpp -lboost_system -lboost_thread -lpthread -lssh
```

Replace `/path/to/boost` and `/path/to/libssh` with the actual paths on your system.

## Usage

After compiling, run the proxy server:

```bash
./socks5_proxy
```

By default, it listens on port `1080` for incoming SOCKS5 connections and connects to an SSH server specified in the code.

## Configuration

Edit the `main` function in `ss.cpp` to configure the proxy and SSH settings:

```cpp
// SOCKS5 Proxy configuration
unsigned short port = 1080;           // Port for the SOCKS5 proxy to listen on
std::size_t thread_pool_size = 1;     // Number of threads to handle connections

// SSH connection details
std::string ssh_host = "80.114.169.130";
int ssh_port = 222;
std::string ssh_user = "admin";
std::string ssh_password = "Tmt$01!";

// SSH options
int verbosity = SSH_LOG_PROTOCOL;     // Logging verbosity level
long timeout = 5;                     // Connection timeout in seconds
std::string ciphers_c_s = "chacha20-poly1305,aes256-gcm@openssh.com,..."; // Ciphers
std::string key_exchange = "curve25519-sha256,...";                      // Key exchange methods
std::string hmac_c_s = "hmac-sha2-256-etm@openssh.com,...";              // HMAC algorithms
std::string hostkeys = "ssh-rsa,ssh-dss,ecdh-sha2-nistp256";             // Host key types
std::string compression = "none";                                        // Compression setting
```

**Note:** Replace the placeholder values with actual configuration details suitable for your environment.

## Detailed Code Explanation

The code consists of several classes and functions that work together to implement the SOCKS5 proxy over SSH. Below is a detailed explanation of each component.

### 1. Logger Class

A thread-safe logging utility that ensures log messages from different threads do not interleave.

**Header:**

```cpp
class Logger {
public:
    template<typename... Args>
    static void log(Args... args);

    template<typename... Args>
    static void error(Args... args);

private:
    static std::mutex mutex_;
};
```

**Methods:**

- `log(Args... args)`: Logs messages to `std::cout`.
- `error(Args... args)`: Logs error messages to `std::cerr`.

**Usage Example:**

```cpp
Logger::log("This is a log message.");
Logger::error("This is an error message.");
```

### 2. SSHManager Class

Manages SSH sessions, including establishing connections, authentication, channel creation, and reconnection logic.

**Header:**

```cpp
class SSHManager {
public:
    SSHManager(const std::string& host, int port, const std::string& user, const std::string& password,
               int verbosity, long timeout,
               const std::string& ciphers_c_s,
               const std::string& key_exchange,
               const std::string& hmac_c_s,
               const std::string& hostkeys,
               const std::string& compression);
    ~SSHManager();

    bool initialize();
    ssh_channel get_channel(const std::string& target_address, int target_port);
    bool is_connected();
    bool reconnect();
    std::string get_error_message();
    void decrement_channel_count();

private:
    // SSH session details
    ssh_session ssh_session_;
    std::mutex mutex_;
    size_t active_channels_;
    bool reconnecting_;
    // Configuration parameters (host, port, user, etc.)
};
```

**Key Functions:**

- `initialize()`: Sets up the SSH session and authenticates.
- `get_channel(target_address, target_port)`: Opens an SSH channel to forward to the target address and port.
- `reconnect()`: Attempts to reconnect the SSH session if disconnected.
- `decrement_channel_count()`: Decreases the count of active channels when a channel is closed.

**Usage in Code:**

Used by `Session` objects to manage SSH channels for forwarding connections.

### 3. Session Class

Handles a single client connection, processing the SOCKS5 protocol and relaying data between the client and the SSH channel.

**Header:**

```cpp
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket client_socket, boost::asio::io_context& io_context,
            std::shared_ptr<SSHManager> ssh_manager);
    void start();

private:
    void handle_handshake();
    void handle_request();
    void send_reply(unsigned char reply_code);
    void connect_to_target_via_ssh();
    void start_relay();
    void relay_client_to_ssh();
    void relay_ssh_to_client();
    void do_close();

    // Member variables (sockets, buffers, target address, etc.)
};
```

**Key Functions:**

- `start()`: Initiates the session by starting the SOCKS5 handshake.
- `handle_handshake()`: Processes the initial SOCKS5 handshake with the client.
- `handle_request()`: Parses the client's request and extracts the target address and port.
- `connect_to_target_via_ssh()`: Obtains an SSH channel to the target server.
- `start_relay()`: Begins relaying data between the client and the SSH channel.
- `do_close()`: Closes sockets and SSH channels, cleaning up resources.

**SOCKS5 Protocol Handling:**

- **Handshake Phase:**
  - Reads version and authentication methods.
  - Replies with the chosen method (no authentication in this implementation).
- **Request Phase:**
  - Reads the request details (command, address type, destination address, and port).
  - Supports IPv4 and domain name address types.
- **Reply Phase:**
  - Sends a response back to the client indicating success or failure.

### 4. Socks5Proxy Class

Listens for incoming client connections and spawns `Session` objects to handle them.

**Header:**

```cpp
class Socks5Proxy {
public:
    Socks5Proxy(boost::asio::io_context& io_context, unsigned short port, std::size_t thread_pool_size,
               const std::string& ssh_host, int ssh_port,
               const std::string& ssh_user, const std::string& ssh_password,
               int verbosity, long timeout,
               const std::string& ciphers_c_s,
               const std::string& key_exchange,
               const std::string& hmac_c_s,
               const std::string& hostkeys,
               const std::string& compression);
    void start();
    void run();

private:
    void do_accept();

    // Member variables (io_context, acceptor, SSHManager, etc.)
};
```

**Key Functions:**

- `start()`: Starts accepting client connections.
- `run()`: Runs the I/O context and thread pool.
- `do_accept()`: Asynchronously accepts new client connections.

### 5. Main Function

Sets up the proxy server configuration and starts it.

**Key Steps:**

- Defines configuration parameters (proxy port, SSH details, SSH options).
- Initializes `boost::asio::io_context` and `Socks5Proxy`.
- Starts the proxy and runs the I/O context.

**Sample Code:**

```cpp
int main() {
    try {
        // Configuration parameters
        unsigned short port = 1080;
        std::size_t thread_pool_size = 1;
        // SSH connection details and options
        // ...

        boost::asio::io_context io_context;
        Socks5Proxy proxy(io_context, port, thread_pool_size, /* SSH parameters */);
        proxy.start();

        Logger::log("Socks5Proxy: Running on port ", port, " with a thread pool of size ", thread_pool_size, ".");
        proxy.run();
    }
    catch (std::exception& e) {
        Logger::error("Main: Exception: ", e.what());
    }
    return 0;
}
```

## How It Works

1. **Client Connection:**
   - A client connects to the proxy on the specified port.
   - The `Socks5Proxy` acceptor accepts the connection and creates a new `Session`.

2. **SOCKS5 Handshake:**
   - The `Session` handles the SOCKS5 handshake, agreeing on no authentication.

3. **SOCKS5 Request Handling:**
   - The `Session` reads the client's request to connect to a target server.
   - Supports both IPv4 addresses and domain names.

4. **SSH Channel Establishment:**
   - The `Session` requests an SSH channel from the `SSHManager` to the target server.
   - If the SSH session is disconnected, the `SSHManager` attempts to reconnect.

5. **Data Relay:**
   - The `Session` starts relaying data between the client and the target server via the SSH channel.
   - Uses asynchronous reads and writes for efficient data transfer.

6. **Session Termination:**
   - When the session ends (e.g., client disconnects), the `Session` closes the sockets and SSH channel.
   - The `SSHManager` updates its active channel count.

## Libraries and Standards Used

- **Boost.Asio**: Provides asynchronous networking functionality.
  - Documentation: [Boost.Asio Documentation](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html)
- **libssh**: Used for SSH connections and channel management.
  - Documentation: [libssh Documentation](https://www.libssh.org/documentation/)
- **C++11 Standard**: Utilizes modern C++ features like smart pointers, lambda expressions, and threading.

## Error Handling and Reconnection Logic

- **SSH Session Management:**
  - The `SSHManager` checks if the SSH session is connected.
  - If not, it attempts to reconnect before establishing new channels.
- **Active Channel Tracking:**
  - Keeps track of active SSH channels to prevent reconnection while channels are in use.
- **Session Error Handling:**
  - The `Session` sends appropriate SOCKS5 error codes back to the client if an error occurs.
  - Ensures that resources are properly cleaned up in case of errors.

## Limitations and Future Enhancements

- **No Authentication for SOCKS5 Clients:**
  - Currently, the proxy does not require clients to authenticate.
  - Future versions could implement SOCKS5 authentication methods.
- **IPv6 Support:**
  - The code has placeholders for IPv6 support but primarily handles IPv4 and domain names.
- **Configuration Flexibility:**
  - Configuration is hard-coded in the `main` function.
  - Could be extended to read from a configuration file or command-line arguments.
- **Additional SOCKS5 Commands:**
  - Only the `CONNECT` command is supported.
  - Could be extended to support `BIND` and `UDP ASSOCIATE`.

## Conclusion

This project provides a robust implementation of a SOCKS5 proxy server in C++ that forwards connections over SSH. By leveraging `Boost.Asio` for networking and `libssh` for SSH session management, it ensures secure and efficient handling of client connections. The code demonstrates effective use of modern C++ features, asynchronous programming, and thread safety.
