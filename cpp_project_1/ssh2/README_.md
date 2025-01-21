# SOCKS5 Proxy over SSH Tunnel

## Introduction

This project implements a SOCKS5 proxy server that forwards client connections through an SSH tunnel to a remote server. It allows users to securely route their network traffic via SSH, providing encryption and security benefits. The proxy server supports multiple tunnels configured via a JSON file.

## Features

- **SOCKS5 Protocol Support**: Handles SOCKS5 client connections, including authentication negotiation and command processing.
- **SSH Tunneling**: Establishes SSH sessions to remote servers and forwards traffic through SSH channels.
- **Concurrent Connections**: Supports multiple simultaneous client connections using asynchronous I/O with Boost.Asio.
- **Configurable Tunnels**: Allows multiple tunnels to be configured via a JSON configuration file.
- **Thread Pool**: Utilizes a thread pool to efficiently handle multiple connections.

## Dependencies

- **Boost.Asio**: For asynchronous networking.
- **nlohmann/json**: For parsing JSON configuration files.
- **libssh**: For SSH session and channel management.
- **C++ Standard Library**: Includes threading, I/O, and other utilities.

## Installation and Compilation

### Prerequisites

Ensure that the following libraries are installed on your system:

- **Boost** (specifically Boost.Asio)
- **nlohmann/json** library
- **libssh**

On Ubuntu/Debian systems, you can install them using:

```bash
sudo apt-get update
sudo apt-get install -y libboost-all-dev libssh-dev
```

For `nlohmann/json`, you can install it via a package manager or include it directly in your project.

### Compilation

To compile the code, use the following command:

```bash
g++ -std=c++17 -o socks5_proxy sw.cpp -lboost_system -lssh -lpthread
```

Ensure that the compiler can find the include paths for the Boost, libssh, and nlohmann/json headers.

If you have included `nlohmann/json.hpp` directly in your project directory, the compiler should find it automatically. Otherwise, you might need to specify the include path:

```bash
g++ -std=c++17 -I/path/to/json/include -o socks5_proxy sw.cpp -lboost_system -lssh -lpthread
```

### Running the Proxy

After compilation, run the proxy server with:

```bash
./socks5_proxy config.json
```

Replace `config.json` with the path to your configuration file.

## Configuration File Format

The configuration file is a JSON file that specifies the tunnels to be established. Each tunnel is an object with the following fields:

- `name` (string): A name for the tunnel (used for logging).
- `host` (string): The SSH server hostname or IP address.
- `port` (integer): The SSH server port (usually 22).
- `username` (string): The SSH username.
- `password` (string): The SSH password.
- `local_port` (integer): The local port on which the SOCKS5 proxy will listen.

### Example Configuration File

```json
[
  {
    "name": "Tunnel1",
    "host": "ssh.example.com",
    "port": 22,
    "username": "user",
    "password": "password",
    "local_port": 1080
  },
  {
    "name": "Tunnel2",
    "host": "ssh.anotherexample.com",
    "port": 22,
    "username": "user2",
    "password": "password2",
    "local_port": 1081
  }
]
```

## Understanding SOCKS5 Proxy

### What is SOCKS5?

SOCKS5 is the latest version of the SOCKS protocol, an Internet protocol that routes network packets between a client and server through a proxy server. SOCKS5 supports advanced networking features, including:

- **Authentication**: Supports various authentication methods to control access to the proxy server.
- **UDP and TCP Support**: Can handle both TCP and UDP traffic.
- **Domain Name Resolution**: Allows the client to request the proxy to perform DNS resolution.

### How Does a SOCKS5 Proxy Work?

A SOCKS5 proxy operates at the session layer (Layer 5) of the OSI model. It acts as an intermediary for clients seeking to communicate with servers. Here's how it works:

1. **Client Connection**: The client establishes a TCP connection to the SOCKS5 proxy server.
2. **Handshake**: The client and proxy perform a handshake to negotiate authentication methods.
3. **Authentication**: If required, the client authenticates using the agreed method.
4. **Request**: The client sends a connection request specifying the desired destination address and port.
5. **Connection**: The proxy server establishes a connection to the target server on behalf of the client.
6. **Data Transfer**: Data is relayed between the client and the server through the proxy.
7. **Termination**: When the session ends, connections are closed.

### SOCKS5 Protocol Steps in Detail

1. **Greeting Request**: The client sends:

   - `VER`: SOCKS version (0x05 for SOCKS5).
   - `NMETHODS`: Number of authentication methods supported.
   - `METHODS`: List of supported authentication methods.

2. **Greeting Response**: The server responds with:

   - `VER`: SOCKS version.
   - `METHOD`: Selected authentication method (or 0xFF if none are acceptable).

3. **Authentication** (if necessary): The client authenticates using the chosen method.

4. **Connection Request**: The client sends:

   - `VER`: SOCKS version.
   - `CMD`: Command code (0x01 for CONNECT).
   - `RSV`: Reserved (0x00).
   - `ATYP`: Address type (0x01 IPv4, 0x03 domain name, 0x04 IPv6).
   - `DST.ADDR`: Destination address.
   - `DST.PORT`: Destination port.

5. **Connection Reply**: The server responds with:

   - `VER`: SOCKS version.
   - `REP`: Reply code (0x00 for success).
   - `RSV`: Reserved (0x00).
   - `ATYP`: Address type.
   - `BND.ADDR`: Server-bound address.
   - `BND.PORT`: Server-bound port.

### Libraries Used for SOCKS5 Implementation

- **Boost.Asio**: Provides the networking and asynchronous I/O functionalities required to implement the SOCKS5 protocol. It handles:

  - Asynchronous socket operations.
  - Timers and strands for thread safety.
  - Error handling and I/O services.

### How the Code Implements SOCKS5

The `Session` class is responsible for handling individual client connections and implementing the SOCKS5 protocol steps.

#### Key Steps:

1. **Handshake Handling (`handle_handshake`)**:

   - Reads the client's greeting request.
   - Parses supported authentication methods.
   - Responds with the chosen method (no authentication in this implementation).

2. **Request Handling (`handle_request`)**:

   - Reads the client's connection request.
   - Parses the destination address and port.
   - Supports IPv4 and domain names (ATYP 0x01 and 0x03).
   - Validates the SOCKS version and command (only CONNECT is supported).

3. **SSH Channel Establishment (`connect_to_target_via_ssh`)**:

   - Uses `SSHManager` to establish an SSH channel to the target address and port.
   - Handles reconnection attempts if the SSH session is lost.

4. **Reply to Client (`send_reply`)**:

   - Sends a connection reply to the client.
   - Includes bound address and port information.

5. **Data Relay (`start_relay`, `relay_client_to_ssh`, `relay_ssh_to_client`)**:

   - Relays data between the client and the target server through the SSH channel.
   - Handles asynchronous reading and writing using Boost.Asio.

6. **Session Cleanup (`do_close`)**:

   - Closes sockets and SSH channels.
   - Ensures resources are properly freed.

### Error Handling

- The code checks for errors at each step and sends appropriate SOCKS5 reply codes.
- It logs errors using the `Logger` class.

## Understanding SSH Tunneling

### What is SSH Tunneling?

SSH tunneling, also known as SSH port forwarding, is a method of transporting arbitrary networking data over an encrypted SSH connection. It can be used to secure otherwise insecure protocols, bypass firewalls, and route traffic through a remote server.

### Types of SSH Port Forwarding

- **Local Port Forwarding**: Forwards traffic from a local port to a remote server.
- **Remote Port Forwarding**: Forwards traffic from a remote server port to a local machine.
- **Dynamic Port Forwarding**: Creates a SOCKS proxy server that can dynamically forward traffic to multiple destinations.

### How Does SSH Work in This Project?

In this project, SSH is used to:

- Establish an encrypted tunnel between the local proxy server and the remote SSH server.
- Create SSH channels that forward traffic to target addresses specified by the client.
- Securely transmit data between the client and the target server through the SSH tunnel.

### SSH Libraries Used

- **libssh**: A C library implementing the SSH protocol, used for:

  - Establishing SSH sessions.
  - Authenticating with the SSH server.
  - Managing SSH channels for forwarding data.

### How the Code Implements SSH Functionality

#### SSHManager Class

The `SSHManager` class encapsulates all SSH-related operations, including session management, authentication, and channel handling.

#### Key Responsibilities:

1. **SSH Session Initialization (`initialize`)**:

   - Creates a new SSH session (`ssh_new`).
   - Sets SSH options such as host, port, username, and authentication methods.
   - Configures SSH algorithms, ciphers, and key exchange methods.
   - Connects to the SSH server (`ssh_connect`).
   - Authenticates with the server using a password (`ssh_userauth_password`).

2. **SSH Channel Management (`get_channel`)**:

   - Opens an SSH channel (`ssh_channel_new`).
   - Opens a forwarding channel to the target address and port (`ssh_channel_open_forward`).
   - Manages active channel counts.

3. **Session Reconnection (`reconnect`)**:

   - Handles reconnection attempts if the SSH session is lost.
   - Ensures that no active channels are open before reconnecting.
   - Re-initializes the SSH session.

4. **Error Handling**:

   - Provides methods to retrieve error messages from the SSH session (`get_error_message`).
   - Logs errors using the `Logger` class.

#### SSH Session Initialization Details

- **Session Creation**:

  ```cpp
  ssh_session_ = ssh_new();
  ```

- **Option Setting**:

  ```cpp
  ssh_options_set(ssh_session_, SSH_OPTIONS_HOST, config_.host.c_str());
  ssh_options_set(ssh_session_, SSH_OPTIONS_PORT, &config_.port);
  ssh_options_set(ssh_session_, SSH_OPTIONS_USER, config_.username.c_str());
  ```

- **Disabling Host Key Checking**:

  - The code sets `SSH_OPTIONS_STRICTHOSTKEYCHECK` to disable host key checking.

  ```cpp
  int strict_host_key_checking_ = 0;
  ssh_options_set(ssh_session_, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict_host_key_checking_);
  ```

  - **Note**: Disabling host key checking can expose the connection to man-in-the-middle attacks. In production, it's recommended to enable strict host key checking.

- **Authentication**:

  ```cpp
  ssh_userauth_password(ssh_session_, nullptr, config_.password.c_str());
  ```

  - **Alternative Authentication**: The code currently uses password authentication. To enhance security, key-based authentication can be implemented using `ssh_userauth_publickey`.

- **SSH Algorithms and Ciphers**:

  - The code sets specific algorithms for ciphers, key exchange, MACs, and host keys to ensure compatibility and security.

  ```cpp
  ssh_options_set(ssh_session_, SSH_OPTIONS_CIPHERS_C_S, ciphers_.c_str());
  ssh_options_set(ssh_session_, SSH_OPTIONS_KEY_EXCHANGE, key_exchange_.c_str());
  ssh_options_set(ssh_session_, SSH_OPTIONS_HMAC_C_S, macs_.c_str());
  ssh_options_set(ssh_session_, SSH_OPTIONS_HOSTKEYS, hostkeys_.c_str());
  ```

#### SSH Channel Management Details

- **Creating a Channel**:

  ```cpp
  ssh_channel channel = ssh_channel_new(ssh_session_);
  ```

- **Opening a Forwarding Channel**:

  ```cpp
  ssh_channel_open_forward(channel, target_address.c_str(), target_port, "127.0.0.1", 0);
  ```

  - **Parameters**:
    - `target_address`: The destination address specified by the client.
    - `target_port`: The destination port specified by the client.
    - `"127.0.0.1"`: The originator IP address (can be set to any valid IP).
    - `0`: The originator port (not significant in this context).

- **Channel Lifecycle**:

  - Channels are opened for each client connection.
  - The `active_channels_` counter keeps track of open channels.
  - When a channel is closed, `decrement_channel_count()` is called.

#### Reconnection Logic

- **When to Reconnect**:

  - If the SSH session is lost or an error occurs while opening a channel.
  - Before reconnecting, it ensures that no active channels are open.

- **Reconnection Steps**:

  1. Sets `reconnecting_` flag to prevent multiple reconnection attempts.
  2. Calls `initialize()` to re-establish the SSH session.
  3. Logs success or failure of the reconnection attempt.

#### Integration with Session Class

- The `Session` class uses `SSHManager` to get an SSH channel for forwarding client requests.

  ```cpp
  ssh_channel channel = ssh_manager_->get_channel(target_address_, target_port_);
  ```

- If `get_channel` returns `nullptr`, it attempts to reconnect using `ssh_manager_->reconnect()` and retries.

- The SSH channel is used to read and write data between the client and the target server.

#### Data Transmission over SSH

- **Writing to SSH Channel**:

  ```cpp
  ssh_channel_write(ssh_channel_, reinterpret_cast<char*>(client_buffer_.data()), bytes_transferred);
  ```

- **Reading from SSH Channel**:

  ```cpp
  int bytes_read = ssh_channel_read_nonblocking(ssh_channel_,
                                                reinterpret_cast<char*>(server_buffer_.data()),
                                                server_buffer_.size(),
                                                0);
  ```

- **Non-blocking I/O**:

  - The code uses non-blocking reads from the SSH channel to integrate smoothly with Boost.Asio's asynchronous model.

### Security Considerations

- **Host Key Verification**:

  - Disabling host key checking (`SSH_OPTIONS_STRICTHOSTKEYCHECK`) can make the connection vulnerable.
  - **Recommendation**: Enable host key checking and manage known hosts files to ensure server authenticity.

- **Password Authentication**:

  - Using passwords can be less secure than key-based authentication.
  - **Recommendation**: Implement SSH key authentication for enhanced security.

- **Algorithm Selection**:

  - The code specifies a list of ciphers and algorithms for compatibility.
  - **Recommendation**: Use strong, up-to-date algorithms and ciphers.

## Code Overview

### Logger Class

A thread-safe logger that outputs messages to `std::cout` for logs and `std::cerr` for errors. It uses a mutex to prevent interleaved output from multiple threads.

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

- **Methods**:
  - `log()`: Logs informational messages.
  - `error()`: Logs error messages.
- **Usage**:
  - `Logger::log("Message");`
  - `Logger::error("Error message");`

### TunnelConfig Struct

Holds the configuration parameters for a tunnel, including SSH connection details and the local port for the proxy server.

```cpp
struct TunnelConfig {
    std::string name;
    std::string host;
    int port;
    std::string username;
    std::string password;
    unsigned short local_port;
};
```

### SSHManager Class

Manages the SSH session for a tunnel. Responsible for:

- Initializing and configuring the SSH session.
- Handling authentication.
- Reconnecting if the connection is lost.
- Managing SSH channels for forwarding.

#### Key Methods:

- **Constructor**: Sets up SSH options and initializes the session.
- `initialize()`: Sets up the SSH session with the specified options and connects to the SSH server.
- `get_channel(const std::string& target_address, int target_port)`: Opens an SSH channel to the target address and port.
- `is_connected()`: Checks if the SSH session is currently connected.
- `reconnect()`: Attempts to re-establish the SSH session.
- `get_error_message()`: Retrieves the last error message from the SSH session.
- `decrement_channel_count()`: Decreases the active channel count when a channel is closed.

#### Usage Example:

```cpp
TunnelConfig config;
// ... set up config ...
SSHManager ssh_manager(config);
if (ssh_manager.initialize()) {
    ssh_channel channel = ssh_manager.get_channel("target.address.com", 80);
    // ... use the channel ...
}
```

### Session Class

Handles individual client connections to the SOCKS5 proxy server. It:

- Performs the SOCKS5 handshake and authentication negotiation.
- Parses client requests to connect to target addresses.
- Establishes SSH channels via `SSHManager`.
- Relays data between the client and the SSH channel.

#### Key Methods:

- `start()`: Initiates the session handling.
- `handle_handshake()`: Processes the initial SOCKS5 handshake.
- `handle_request()`: Parses the client's connection request.
- `connect_to_target_via_ssh()`: Establishes an SSH channel to the target.
- `send_reply(unsigned char reply_code)`: Sends a SOCKS5 reply to the client.
- `start_relay()`: Begins relaying data between the client and the SSH channel.
- `relay_client_to_ssh()`: Forwards data from the client to the SSH channel.
- `relay_ssh_to_client()`: Forwards data from the SSH channel to the client.
- `do_close()`: Closes the client socket and SSH channel.

#### Workflow:

1. **Handshake**: Negotiates authentication methods with the client.
2. **Request Handling**: Parses the client's request to connect to a target address.
3. **SSH Channel Establishment**: Uses `SSHManager` to create an SSH channel to the target.
4. **Data Relay**: Relays data between the client and the target over the SSH channel.
5. **Cleanup**: Closes connections and cleans up resources when done.

### Socks5Proxy Class

Listens for incoming client connections on the specified local port and creates `Session` instances to handle them.

#### Key Methods:

- `start()`: Begins accepting client connections.
- `do_accept()`: Asynchronously accepts new client connections and spawns sessions.

#### Usage Example:

```cpp
boost::asio::io_context io_context;
TunnelConfig config;
// ... set up config ...
Socks5Proxy proxy(io_context, config);
proxy.start();
io_context.run();
```

### Main Function

- Parses the configuration file to load tunnel configurations.
- Sets up an `io_context` and a thread pool for asynchronous operations.
- Creates and starts `Socks5Proxy` instances for each tunnel.
- Runs the `io_context` to process asynchronous events.

#### Workflow:

1. **Configuration Parsing**: Reads the JSON configuration file and populates a list of `TunnelConfig` objects.
2. **Proxy Initialization**: For each tunnel configuration, creates a `Socks5Proxy` instance and starts it.
3. **Thread Pool Setup**: Determines the number of threads to use and starts a thread pool.
4. **Event Loop**: Runs the Boost.Asio `io_context` to handle asynchronous events.

## Usage Notes

- **Security**: The code uses password authentication for SSH. For enhanced security, consider using key-based authentication.
- **Error Handling**: The code logs errors to `std::cerr`. Ensure you monitor the logs to troubleshoot any issues.
- **Firewall**: Ensure that the local ports specified in the configuration are open and not blocked by a firewall.

## Limitations and Future Improvements

- **IPv6 Support**: The code mentions IPv6 but currently handles IPv4 addresses. Adding full IPv6 support would enhance compatibility.
- **Authentication Methods**: The SOCKS5 proxy currently supports "no authentication" method. Implementing username/password authentication could enhance security.
- **Configuration Options**: Additional SSH options (e.g., key-based authentication) can be added to the configuration file.
- **Logging Enhancements**: Implementing a more sophisticated logging mechanism could improve maintainability.

## License

This project is released under the MIT License.

---

# SOCKS5 Прокси через SSH Туннель

## Введение

Данный проект реализует SOCKS5 прокси-сервер, который перенаправляет клиентские подключения через SSH-туннель на удалённый сервер. Это позволяет пользователям безопасно маршрутизировать свой сетевой трафик через SSH, обеспечивая шифрование и преимущества безопасности. Прокси-сервер поддерживает несколько туннелей, настроенных через JSON-файл.

## Особенности

- **Поддержка протокола SOCKS5**: Обрабатывает подключения клиентов SOCKS5, включая согласование аутентификации и обработку команд.
- **SSH Туннелирование**: Устанавливает SSH-сессии к удалённым серверам и перенаправляет трафик через SSH-каналы.
- **Конкурентные подключения**: Поддерживает множественные одновременные клиентские подключения, используя асинхронный ввод-вывод с Boost.Asio.
- **Настраиваемые туннели**: Позволяет настраивать несколько туннелей через JSON-конфигурационный файл.
- **Пул потоков**: Использует пул потоков для эффективной обработки множественных подключений.

## Зависимости

- **Boost.Asio**: Для асинхронной работы с сетью.
- **nlohmann/json**: Для парсинга JSON-конфигурационных файлов.
- **libssh**: Для управления SSH-сессиями и каналами.
- **Стандартная библиотека C++**: Включает потоки, ввод-вывод и другие утилиты.

## Установка и Компиляция

### Предварительные требования

Убедитесь, что следующие библиотеки установлены на вашей системе:

- **Boost** (в частности Boost.Asio)
- **Библиотека nlohmann/json**
- **libssh**

На системах Ubuntu/Debian вы можете установить их с помощью:

```bash
sudo apt-get update
sudo apt-get install -y libboost-all-dev libssh-dev
```

Для `nlohmann/json` вы можете установить её через менеджер пакетов или включить непосредственно в ваш проект.

### Компиляция

Для компиляции кода используйте следующую команду:

```bash
g++ -std=c++17 -o socks5_proxy sw.cpp -lboost_system -lssh -lpthread
```

Убедитесь, что компилятор может найти пути включения для заголовков Boost, libssh и nlohmann/json.

Если вы включили `nlohmann/json.hpp` непосредственно в директорию вашего проекта, компилятор найдёт её автоматически. В противном случае вам может потребоваться указать путь включения:

```bash
g++ -std=c++17 -I/путь/к/json/include -o socks5_proxy sw.cpp -lboost_system -lssh -lpthread
```

### Запуск Прокси

После компиляции запустите прокси-сервер с помощью:

```bash
./socks5_proxy config.json
```

Замените `config.json` на путь к вашему конфигурационному файлу.

## Формат Конфигурационного Файла

Конфигурационный файл представляет собой JSON-файл, который определяет туннели для установления. Каждый туннель — это объект со следующими полями:

- `name` (строка): Имя туннеля (используется для логирования).
- `host` (строка): Имя хоста или IP-адрес SSH-сервера.
- `port` (целое число): Порт SSH-сервера (обычно 22).
- `username` (строка): Имя пользователя SSH.
- `password` (строка): Пароль SSH.
- `local_port` (целое число): Локальный порт, на котором будет слушать SOCKS5 прокси.

### Пример Конфигурационного Файла

```json
[
  {
    "name": "Tunnel1",
    "host": "ssh.example.com",
    "port": 22,
    "username": "user",
    "password": "password",
    "local_port": 1080
  },
  {
    "name": "Tunnel2",
    "host": "ssh.anotherexample.com",
    "port": 22,
    "username": "user2",
    "password": "password2",
    "local_port": 1081
  }
]
```

## Понимание SOCKS5 Прокси

### Что такое SOCKS5?

SOCKS5 — это последняя версия протокола SOCKS, интернет-протокола, который маршрутизирует сетевые пакеты между клиентом и сервером через прокси-сервер. SOCKS5 поддерживает расширенные сетевые функции, включая:

- **Аутентификация**: Поддерживает различные методы аутентификации для контроля доступа к прокси-серверу.
- **Поддержка UDP и TCP**: Может обрабатывать как TCP, так и UDP трафик.
- **Разрешение доменных имён**: Позволяет клиенту запрашивать прокси для выполнения DNS-разрешения.

### Как работает SOCKS5 Прокси?

SOCKS5 прокси работает на сеансовом уровне (Уровень 5) модели OSI. Он действует как посредник для клиентов, желающих связаться с серверами. Вот как это работает:

1. **Подключение Клиента**: Клиент устанавливает TCP-соединение с SOCKS5 прокси-сервером.
2. **Рукопожатие**: Клиент и прокси выполняют рукопожатие для согласования методов аутентификации.
3. **Аутентификация**: Если требуется, клиент аутентифицируется с использованием согласованного метода.
4. **Запрос**: Клиент отправляет запрос на подключение, указывая желаемый адрес и порт назначения.
5. **Соединение**: Прокси-сервер устанавливает соединение с целевым сервером от имени клиента.
6. **Передача Данных**: Данные передаются между клиентом и сервером через прокси.
7. **Завершение**: Когда сессия заканчивается, соединения закрываются.

### Подробные Шаги Протокола SOCKS5

1. **Приветствие (Greeting Request)**: Клиент отправляет:

   - `VER`: Версия SOCKS (0x05 для SOCKS5).
   - `NMETHODS`: Количество поддерживаемых методов аутентификации.
   - `METHODS`: Список поддерживаемых методов аутентификации.

2. **Ответ Приветствия (Greeting Response)**: Сервер отвечает:

   - `VER`: Версия SOCKS.
   - `METHOD`: Выбранный метод аутентификации (или 0xFF, если ни один не приемлем).

3. **Аутентификация** (если необходимо): Клиент аутентифицируется с использованием выбранного метода.

4. **Запрос на Подключение (Connection Request)**: Клиент отправляет:

   - `VER`: Версия SOCKS.
   - `CMD`: Код команды (0x01 для CONNECT).
   - `RSV`: Зарезервировано (0x00).
   - `ATYP`: Тип адреса (0x01 IPv4, 0x03 доменное имя, 0x04 IPv6).
   - `DST.ADDR`: Адрес назначения.
   - `DST.PORT`: Порт назначения.

5. **Ответ на Подключение (Connection Reply)**: Сервер отвечает:

   - `VER`: Версия SOCKS.
   - `REP`: Код ответа (0x00 для успеха).
   - `RSV`: Зарезервировано (0x00).
   - `ATYP`: Тип адреса.
   - `BND.ADDR`: Привязанный адрес сервера.
   - `BND.PORT`: Привязанный порт сервера.

### Используемые Библиотеки для Реализации SOCKS5

- **Boost.Asio**: Предоставляет функциональность для сетевого взаимодействия и асинхронного ввода-вывода, необходимую для реализации протокола SOCKS5. Он обрабатывает:

  - Асинхронные операции с сокетами.
  - Таймеры и `strand` для обеспечения потокобезопасности.
  - Обработку ошибок и I/O сервисы.

### Как Код Реализует SOCKS5

Класс `Session` отвечает за обработку индивидуальных клиентских подключений и реализацию шагов протокола SOCKS5.

#### Ключевые Шаги:

1. **Обработка Рукопожатия (`handle_handshake`)**:

   - Читает приветствие от клиента.
   - Разбирает поддерживаемые методы аутентификации.
   - Отправляет ответ с выбранным методом (в данной реализации — без аутентификации).

2. **Обработка Запроса (`handle_request`)**:

   - Читает запрос на подключение от клиента.
   - Разбирает адрес и порт назначения.
   - Поддерживает IPv4 и доменные имена (ATYP 0x01 и 0x03).
   - Проверяет версию SOCKS и команду (поддерживается только CONNECT).

3. **Установка SSH-Канала (`connect_to_target_via_ssh`)**:

   - Использует `SSHManager` для установления SSH-канала к целевому адресу и порту.
   - Обрабатывает попытки переподключения, если SSH-сессия потеряна.

4. **Ответ Клиенту (`send_reply`)**:

   - Отправляет ответ на запрос подключения клиенту.
   - Включает информацию о привязанном адресе и порте.

5. **Перенаправление Данных (`start_relay`, `relay_client_to_ssh`, `relay_ssh_to_client`)**:

   - Перенаправляет данные между клиентом и целевым сервером через SSH-канал.
   - Обрабатывает асинхронное чтение и запись с использованием Boost.Asio.

6. **Очистка Сессии (`do_close`)**:

   - Закрывает сокеты и SSH-каналы.
   - Гарантирует, что ресурсы правильно освобождены.

### Обработка Ошибок

- Код проверяет ошибки на каждом шаге и отправляет соответствующие коды ответа SOCKS5.
- Ошибки логируются с помощью класса `Logger`.

## Понимание SSH Туннелирования

### Что такое SSH Туннелирование?

SSH туннелирование, также известное как перенаправление портов SSH, — это метод транспортировки произвольных сетевых данных через зашифрованное SSH-соединение. Это может быть использовано для защиты небезопасных протоколов, обхода брандмауэров и маршрутизации трафика через удалённый сервер.

### Типы Перенаправления Портов SSH

- **Локальное Перенаправление Портов**: Перенаправляет трафик с локального порта на удалённый сервер.
- **Удалённое Перенаправление Портов**: Перенаправляет трафик с порта удалённого сервера на локальную машину.
- **Динамическое Перенаправление Портов**: Создаёт SOCKS прокси-сервер, который может динамически перенаправлять трафик на несколько направлений.

### Как SSH Работает в Этом Проекте?

В этом проекте SSH используется для:

- Установления зашифрованного туннеля между локальным прокси-сервером и удалённым SSH-сервером.
- Создания SSH-каналов, которые перенаправляют трафик на целевые адреса, указанные клиентом.
- Безопасной передачи данных между клиентом и целевым сервером через SSH-туннель.

### Используемые SSH Библиотеки

- **libssh**: C-библиотека, реализующая протокол SSH, используется для:

  - Установления SSH-сессий.
  - Аутентификации с SSH-сервером.
  - Управления SSH-каналами для передачи данных.

### Как Код Реализует Функциональность SSH

#### Класс SSHManager

Класс `SSHManager` инкапсулирует все операции, связанные с SSH, включая управление сессией, аутентификацию и обработку каналов.

#### Основные Ответственности:

1. **Инициализация SSH Сессии (`initialize`)**:

   - Создаёт новую SSH-сессию (`ssh_new`).
   - Устанавливает опции SSH, такие как хост, порт, имя пользователя и методы аутентификации.
   - Настраивает SSH алгоритмы, шифры и методы обмена ключами.
   - Подключается к SSH-серверу (`ssh_connect`).
   - Аутентифицируется с сервером, используя пароль (`ssh_userauth_password`).

2. **Управление SSH-Каналами (`get_channel`)**:

   - Открывает SSH-канал (`ssh_channel_new`).
   - Открывает перенаправленный канал к целевому адресу и порту (`ssh_channel_open_forward`).
   - Управляет счётчиком активных каналов.

3. **Переподключение Сессии (`reconnect`)**:

   - Обрабатывает попытки переподключения, если SSH-сессия потеряна.
   - Гарантирует, что перед переподключением нет открытых активных каналов.
   - Повторно инициализирует SSH-сессию.

4. **Обработка Ошибок**:

   - Предоставляет методы для получения сообщений об ошибках из SSH-сессии (`get_error_message`).
   - Логирует ошибки с помощью класса `Logger`.

#### Детали Инициализации SSH Сессии

- **Создание Сессии**:

  ```cpp
  ssh_session_ = ssh_new();
  ```

- **Установка Опций**:

  ```cpp
  ssh_options_set(ssh_session_, SSH_OPTIONS_HOST, config_.host.c_str());
  ssh_options_set(ssh_session_, SSH_OPTIONS_PORT, &config_.port);
  ssh_options_set(ssh_session_, SSH_OPTIONS_USER, config_.username.c_str());
  ```

- **Отключение Проверки Ключа Хоста**:

  - Код устанавливает `SSH_OPTIONS_STRICTHOSTKEYCHECK`, чтобы отключить проверку ключа хоста.

  ```cpp
  int strict_host_key_checking_ = 0;
  ssh_options_set(ssh_session_, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict_host_key_checking_);
  ```

  - **Примечание**: Отключение проверки ключа хоста может подвергнуть соединение атакам "человек посередине". В производственной среде рекомендуется включать строгую проверку ключа хоста.

- **Аутентификация**:

  ```cpp
  ssh_userauth_password(ssh_session_, nullptr, config_.password.c_str());
  ```

  - **Альтернативная Аутентификация**: В настоящее время код использует аутентификацию по паролю. Для повышения безопасности можно реализовать аутентификацию по ключу с помощью `ssh_userauth_publickey`.

- **Алгоритмы и Шифры SSH**:

  - Код устанавливает конкретные алгоритмы для шифров, обмена ключами, MAC и ключей хоста для обеспечения совместимости и безопасности.

  ```cpp
  ssh_options_set(ssh_session_, SSH_OPTIONS_CIPHERS_C_S, ciphers_.c_str());
  ssh_options_set(ssh_session_, SSH_OPTIONS_KEY_EXCHANGE, key_exchange_.c_str());
  ssh_options_set(ssh_session_, SSH_OPTIONS_HMAC_C_S, macs_.c_str());
  ssh_options_set(ssh_session_, SSH_OPTIONS_HOSTKEYS, hostkeys_.c_str());
  ```

#### Детали Управления SSH-Каналами

- **Создание Канала**:

  ```cpp
  ssh_channel channel = ssh_channel_new(ssh_session_);
  ```

- **Открытие Перенаправленного Канала**:

  ```cpp
  ssh_channel_open_forward(channel, target_address.c_str(), target_port, "127.0.0.1", 0);
  ```

  - **Параметры**:
    - `target_address`: Адрес назначения, указанный клиентом.
    - `target_port`: Порт назначения, указанный клиентом.
    - `"127.0.0.1"`: IP-адрес инициатора (может быть установлен на любой действительный IP).
    - `0`: Порт инициатора (не имеет значения в данном контексте).

- **Жизненный Цикл Канала**:

  - Каналы открываются для каждого клиентского подключения.
  - Счётчик `active_channels_` отслеживает открытые каналы.
  - Когда канал закрывается, вызывается `decrement_channel_count()`.

#### Логика Переподключения

- **Когда Переподключаться**:

  - Если SSH-сессия потеряна или возникает ошибка при открытии канала.
  - Перед переподключением гарантируется, что нет открытых активных каналов.

- **Шаги Переподключения**:

  1. Устанавливается флаг `reconnecting_`, чтобы предотвратить множественные попытки переподключения.
  2. Вызывается `initialize()` для повторного установления SSH-сессии.
  3. Логируется успех или неудача попытки переподключения.

#### Интеграция с Классом Session

- Класс `Session` использует `SSHManager` для получения SSH-канала для перенаправления клиентских запросов.

  ```cpp
  ssh_channel channel = ssh_manager_->get_channel(target_address_, target_port_);
  ```

- Если `get_channel` возвращает `nullptr`, он пытается переподключиться с помощью `ssh_manager_->reconnect()` и повторяет попытку.

- SSH-канал используется для чтения и записи данных между клиентом и целевым сервером.

#### Передача Данных через SSH

- **Запись в SSH-канал**:

  ```cpp
  ssh_channel_write(ssh_channel_, reinterpret_cast<char*>(client_buffer_.data()), bytes_transferred);
  ```

- **Чтение из SSH-канала**:

  ```cpp
  int bytes_read = ssh_channel_read_nonblocking(ssh_channel_,
                                                reinterpret_cast<char*>(server_buffer_.data()),
                                                server_buffer_.size(),
                                                0);
  ```

- **Неблокирующий Ввод-Вывод**:

  - Код использует неблокирующее чтение из SSH-канала для плавной интеграции с асинхронной моделью Boost.Asio.

### Соображения Безопасности

- **Проверка Ключа Хоста**:

  - Отключение проверки ключа хоста (`SSH_OPTIONS_STRICTHOSTKEYCHECK`) может сделать соединение уязвимым.
  - **Рекомендация**: Включите проверку ключа хоста и управляйте файлами известных хостов для обеспечения подлинности сервера.

- **Аутентификация по Паролю**:

  - Использование паролей может быть менее безопасным, чем аутентификация по ключу.
  - **Рекомендация**: Реализуйте аутентификацию по ключу SSH для повышения безопасности.

- **Выбор Алгоритмов**:

  - Код задаёт список шифров и алгоритмов для совместимости.
  - **Рекомендация**: Используйте сильные, современные алгоритмы и шифры.

## Обзор Кода

### Класс Logger

Потокобезопасный логгер, который выводит сообщения в `std::cout` для логов и `std::cerr` для ошибок. Использует мьютекс для предотвращения переплетения вывода от нескольких потоков.

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

- **Методы**:
  - `log()`: Логирует информационные сообщения.
  - `error()`: Логирует сообщения об ошибках.
- **Использование**:
  - `Logger::log("Сообщение");`
  - `Logger::error("Сообщение об ошибке");`

### Структура TunnelConfig

Содержит параметры конфигурации для туннеля, включая детали подключения по SSH и локальный порт для прокси-сервера.

```cpp
struct TunnelConfig {
    std::string name;
    std::string host;
    int port;
    std::string username;
    std::string password;
    unsigned short local_port;
};
```

### Класс SSHManager

Управляет SSH-сессией для туннеля. Отвечает за:

- Инициализацию и настройку SSH-сессии.
- Обработку аутентификации.
- Переподключение в случае потери соединения.
- Управление SSH-каналами для перенаправления.

#### Основные Методы:

- **Конструктор**: Настраивает опции SSH и инициализирует сессию.
- `initialize()`: Настраивает SSH-сессию с указанными опциями и подключается к SSH-серверу.
- `get_channel(const std::string& target_address, int target_port)`: Открывает SSH-канал к целевому адресу и порту.
- `is_connected()`: Проверяет, подключена ли SSH-сессия в данный момент.
- `reconnect()`: Пытается восстановить SSH-сессию.
- `get_error_message()`: Получает последнее сообщение об ошибке из SSH-сессии.
- `decrement_channel_count()`: Уменьшает счётчик активных каналов при закрытии канала.

#### Пример Использования:

```cpp
TunnelConfig config;
// ... настройка config ...
SSHManager ssh_manager(config);
if (ssh_manager.initialize()) {
    ssh_channel channel = ssh_manager.get_channel("target.address.com", 80);
    // ... использование канала ...
}
```

### Класс Session

Обрабатывает индивидуальные клиентские подключения к SOCKS5 прокси-серверу. Он:

- Выполняет рукопожатие SOCKS5 и согласование аутентификации.
- Разбирает запросы клиентов на подключение к целевым адресам.
- Устанавливает SSH-каналы через `SSHManager`.
- Перенаправляет данные между клиентом и SSH-каналом.

#### Основные Методы:

- `start()`: Инициализирует обработку сессии.
- `handle_handshake()`: Обрабатывает начальное рукопожатие SOCKS5.
- `handle_request()`: Разбирает запрос клиента на соединение.
- `connect_to_target_via_ssh()`: Устанавливает SSH-канал к цели.
- `send_reply(unsigned char reply_code)`: Отправляет ответ SOCKS5 клиенту.
- `start_relay()`: Начинает перенаправление данных между клиентом и SSH-каналом.
- `relay_client_to_ssh()`: Пересылает данные от клиента к SSH-каналу.
- `relay_ssh_to_client()`: Пересылает данные от SSH-канала к клиенту.
- `do_close()`: Закрывает сокет клиента и SSH-канал.

#### Рабочий Процесс:

1. **Рукопожатие**: Согласовывает методы аутентификации с клиентом.
2. **Обработка Запроса**: Разбирает запрос клиента на подключение к целевому адресу.
3. **Установка SSH-Канала**: Использует `SSHManager` для создания SSH-канала к цели.
4. **Перенаправление Данных**: Перенаправляет данные между клиентом и целью через SSH-канал.
5. **Очистка**: Закрывает соединения и освобождает ресурсы после завершения.

### Класс Socks5Proxy

Слушает входящие клиентские подключения на указанном локальном порту и создаёт экземпляры `Session` для их обработки.

#### Основные Методы:

- `start()`: Начинает приём клиентских подключений.
- `do_accept()`: Асинхронно принимает новые клиентские подключения и запускает сессии.

#### Пример Использования:

```cpp
boost::asio::io_context io_context;
TunnelConfig config;
// ... настройка config ...
Socks5Proxy proxy(io_context, config);
proxy.start();
io_context.run();
```

### Главная Функция

- Разбирает конфигурационный файл для загрузки конфигураций туннелей.
- Настраивает `io_context` и пул потоков для асинхронных операций.
- Создаёт и запускает экземпляры `Socks5Proxy` для каждого туннеля.
- Запускает `io_context` для обработки асинхронных событий.

#### Рабочий Процесс:

1. **Парсинг Конфигурации**: Читает JSON-конфигурационный файл и заполняет список объектов `TunnelConfig`.
2. **Инициализация Прокси**: Для каждой конфигурации туннеля создаёт экземпляр `Socks5Proxy` и запускает его.
3. **Настройка Пула Потоков**: Определяет количество используемых потоков и запускает пул потоков.
4. **Цикл Событий**: Запускает `io_context` Boost.Asio для обработки асинхронных событий.

## Примечания по Использованию

- **Безопасность**: Код использует аутентификацию по паролю для SSH. Для повышения безопасности рекомендуется использовать аутентификацию по ключу.
- **Обработка Ошибок**: Код выводит ошибки в `std::cerr`. Убедитесь, что вы отслеживаете логи для устранения неполадок.
- **Брандмауэр**: Убедитесь, что локальные порты, указанные в конфигурации, открыты и не блокируются брандмауэром.

## Ограничения и Будущие Улучшения

- **Поддержка IPv6**: Код упоминает IPv6, но в настоящее время обрабатывает IPv4 адреса. Добавление полной поддержки IPv6 улучшит совместимость.
- **Методы Аутентификации**: Прокси SOCKS5 в настоящее время поддерживает метод "без аутентификации". Реализация аутентификации по имени пользователя и паролю может повысить безопасность.
- **Опции Конфигурации**: Дополнительные опции SSH (например, аутентификация по ключу) могут быть добавлены в конфигурационный файл.
- **Улучшение Логирования**: Реализация более сложного механизма логирования может улучшить поддерживаемость.

## Лицензия

Этот проект распространяется под лицензией MIT.