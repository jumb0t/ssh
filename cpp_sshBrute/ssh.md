# SSH Checker

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Using CMake](#using-cmake)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Example](#example)
- [Project Structure](#project-structure)
- [Classes and Functions](#classes-and-functions)
  - [Classes](#classes)
    - [Credential](#credential)
    - [SafeQueue](#safequeue)
    - [SSHSession](#sshsession)
    - [ThreadPool](#threadpool)
  - [Functions](#functions)
    - [read_ips](#read_ips)
    - [read_usernames_passwords](#read_usernames_passwords)
    - [parse_ports](#parse_ports)
    - [read_user_pass](#read_user_pass)
    - [setup_logging](#setup_logging)
    - [check_credentials](#check_credentials)
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

## Overview

**SSH Checker** is a robust and efficient C++ application designed for mass verification of SSH credentials across multiple servers. It leverages multithreading to handle numerous authentication attempts concurrently, significantly improving performance and reducing execution time. The tool utilizes `libssh` for SSH operations and `log4cpp` for comprehensive logging, ensuring that all activities are meticulously recorded for auditing and debugging purposes.

Key functionalities include:

- **Mass SSH Credential Verification:** Efficiently verify multiple username and password combinations across various IP addresses and ports.
- **Multithreading Support:** Utilize multiple threads to perform concurrent SSH authentication attempts, enhancing performance.
- **Detailed Logging:** Comprehensive logging with multiple levels (`DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`) both to console and log files.
- **Configurable Parameters:** Customize input files, ports, timeouts, thread counts, and authentication methods via command-line options.
- **Build Modes:** Support for `Debug` and `Release` build modes with corresponding logging levels.
- **RAII for Resource Management:** Ensures safe and efficient management of SSH sessions and other resources through RAII principles.

## Features

- **Mass SSH Credential Verification:** Automate the process of checking multiple SSH credentials across numerous servers.
- **Multithreading:** Implemented using a thread pool to manage concurrent tasks, maximizing CPU utilization.
- **Comprehensive Logging:** Logs detailed information about each step of the authentication process, aiding in troubleshooting and auditing.
- **Flexible Configuration:** Easily configure the tool using command-line arguments to specify input files, ports, timeouts, and more.
- **Error Handling:** Robust error handling mechanisms to gracefully manage and log unexpected issues.
- **Scalability:** Capable of handling large-scale authentication attempts efficiently.

## Prerequisites

Before building and running SSH Checker, ensure that the following dependencies are installed on your system:

- **C++ Compiler:** GCC, Clang, or MSVC with C++20 support.
- **CMake:** Version 3.10 or higher.
- **libssh:** SSH library for secure connections.
- **log4cpp:** C++ library for logging.
- **OpenSSL:** Required by libssh for encryption.
- **zlib:** Compression library.
- **Build Essentials:** Make sure you have essential build tools installed.

### Installing Dependencies on Ubuntu

```bash
sudo apt-get update
sudo apt-get install build-essential cmake liblog4cpp5-dev libssh-dev libssl-dev zlib1g-dev
```

## Installation

### Using CMake

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/ssh_checker.git
   cd ssh_checker
   ```

2. **Create Build Directory**

   ```bash
   mkdir build
   cd build
   ```

3. **Configure the Project**

   - **For Debug Build:**

     ```bash
     cmake .. -DCMAKE_BUILD_TYPE=Debug
     ```

   - **For Release Build:**

     ```bash
     cmake .. -DCMAKE_BUILD_TYPE=Release
     ```

4. **Build the Project**

   ```bash
   make
   ```

5. **Executable**

   After successful build, the executable `ssh_checker` (or `ssh_checker.exe` on Windows) will be available in the `build` directory.

## Usage

### Command-Line Options

SSH Checker provides a variety of command-line options to customize its behavior:

| Short | Long              | Argument        | Description                                                                 |
|-------|-------------------|-----------------|-----------------------------------------------------------------------------|
| `-i`  | `--ips`           | `FILE`          | Path to the file containing IP addresses.                                  |
| `-u`  | `--usernames`     | `FILE`          | Path to the file containing usernames.                                     |
| `-w`  | `--passwords`     | `FILE`          | Path to the file containing passwords.                                     |
| `-p`  | `--ports`         | `PORTS`         | List of ports separated by commas and/or ranges (e.g., `22,2222,22-2020`). |
| `-t`  | `--timeout`       | `SECONDS`       | Connection timeout in seconds (default: `10`).                             |
| `-m`  | `--max-threads`   | `NUM`           | Maximum number of concurrent threads (default: `10`).                      |
| `-c`  | `--config`        | `FILE`          | Path to the SSH configuration file (default: `/etc/ssh/ssh_config`).       |
| `-a`  | `--password-auth` | No argument     | Enable both password and public key authentication.                         |
| `-d`  | `--debug`         | No argument     | Enable debug mode with detailed logging.                                   |
| `-h`  | `--help`          | No argument     | Display help message and exit.                                              |

### Example

#### Running in Debug Mode

```bash
./ssh_checker \
  --ips data/ips.txt \
  --usernames data/usernames.txt \
  --passwords data/passwords.txt \
  --ports 22,2222,22-2020 \
  --timeout 15 \
  --max-threads 20 \
  --config /etc/ssh/ssh_config \
  --password-auth \
  --debug
```

#### Running in Release Mode

```bash
./ssh_checker \
  --ips data/ips.txt \
  --usernames data/usernames.txt \
  --passwords data/passwords.txt \
  --ports 22,2222,22-2020 \
  --timeout 15 \
  --max-threads 20 \
  --config /etc/ssh/ssh_config \
  --password-auth
```

### Input Files

#### `ips.txt`

List of IP addresses to target, one per line.

```
192.168.1.10
192.168.1.11
192.168.1.12
```

#### `usernames.txt`

List of usernames, one per line.

```
user1
user2
user3
```

#### `passwords.txt`

List of passwords, one per line corresponding to the usernames.

```
password1
password2
password3
```

## Project Structure

```
ssh_checker/
├── CMakeLists.txt         # CMake build configuration
├── ssh_checker.cpp        # Main application source code
├── include/               # Header files (if any)
├── logs/                  # Directory for log files
│   └── ssh_checker.log
├── data/                  # Directory for input data files
│   ├── ips.txt
│   ├── usernames.txt
│   └── passwords.txt
└── build/                 # Build directory (created after running CMake)
```

## Classes and Functions

### Classes

#### `Credential`

```cpp
struct Credential {
    std::string username; ///< Username for SSH authentication
    std::string password; ///< Password for SSH authentication
    std::string ip;       ///< IP address of the target host
    int port;             ///< SSH port number
};
```

- **Description:**  
  Represents a set of SSH credentials along with the target host's IP address and port.

- **Data Members:**
  - `username`: The username used for SSH authentication.
  - `password`: The corresponding password for the username.
  - `ip`: The IP address of the SSH server to connect to.
  - `port`: The port number on which the SSH server is listening.

- **Usage:**  
  Instances of `Credential` are created for each combination of username, password, IP, and port that needs to be tested.

#### `SafeQueue<T>`

```cpp
template <typename T>
class SafeQueue {
private:
    std::queue<T> queue_;                ///< Internal queue to store elements
    std::mutex mtx_;                     ///< Mutex to protect the queue
    std::condition_variable cv_;         ///< Condition variable for synchronization

public:
    /**
     * @brief Adds an element to the queue in a thread-safe manner.
     *
     * @param value The element to be added.
     */
    void enqueue(T value);

    /**
     * @brief Removes and retrieves the front element from the queue in a thread-safe manner.
     *
     * This function will block if the queue is empty until an element is available or until
     * a shutdown signal is received.
     *
     * @param value Reference to store the retrieved element.
     * @return true If an element was successfully retrieved.
     * @return false If the queue was empty and a shutdown signal was received.
     */
    bool dequeue(T &value);

    /**
     * @brief Checks whether the queue is empty.
     *
     * @return true If the queue is empty.
     * @return false If the queue has one or more elements.
     */
    bool empty();

    /**
     * @brief Notifies all waiting threads to stop waiting, typically used during shutdown.
     */
    void notify_all();
};
```

- **Description:**  
  A thread-safe queue implementation using mutexes and condition variables. Facilitates safe enqueueing and dequeueing of tasks in a multithreaded environment.

- **Member Functions:**
  - `enqueue(T value)`: Adds an element to the queue in a thread-safe manner and notifies one waiting thread.
  - `dequeue(T &value)`: Attempts to remove the front element from the queue. If the queue is empty, it waits until an element is available or a shutdown signal is received.
  - `empty()`: Returns whether the queue is empty.
  - `notify_all()`: Notifies all waiting threads, typically used to signal shutdown.

- **Usage:**  
  Used internally by classes managing task queues to ensure safe access across multiple threads.

#### `SSHSession`

```cpp
class SSHSession {
public:
    /**
     * @brief Constructs an SSHSession object and initializes a new SSH session.
     *
     * Throws a runtime exception if the session cannot be created.
     */
    SSHSession();

    /**
     * @brief Destructs the SSHSession object, ensuring the SSH session is properly disconnected and freed.
     */
    ~SSHSession();

    /**
     * @brief Retrieves the underlying ssh_session object.
     *
     * @return ssh_session The SSH session pointer.
     */
    ssh_session get() const;

    // Delete copy constructor and copy assignment operator to prevent copying
    SSHSession(const SSHSession&) = delete;
    SSHSession& operator=(const SSHSession&) = delete;

    // Allow move constructor and move assignment operator for resource transfer
    SSHSession(SSHSession&& other) noexcept;
    SSHSession& operator=(SSHSession&& other) noexcept;

private:
    ssh_session session_; ///< Pointer to the SSH session.
};
```

- **Description:**  
  Manages an SSH session using RAII (Resource Acquisition Is Initialization) principles. Ensures that SSH sessions are properly disconnected and freed when the object goes out of scope.

- **Member Functions:**
  - `SSHSession()`: Initializes a new SSH session. Throws an exception if initialization fails.
  - `~SSHSession()`: Disconnects and frees the SSH session if it exists.
  - `get()`: Returns the underlying `ssh_session` pointer for further configuration and usage.
  - **Deleted Functions:**  
    Copy constructor and copy assignment operator are deleted to prevent accidental copying of the session.
  - **Move Functions:**  
    Move constructor and move assignment operator are defined to allow transferring ownership of the session.

- **Usage:**  
  Instances of `SSHSession` are used within other classes or functions to manage the lifecycle of SSH connections safely.

#### `ThreadPool`

```cpp
class ThreadPool {
public:
    /**
     * @brief Constructs a ThreadPool with the specified number of worker threads.
     *
     * @param threads The number of worker threads to initialize.
     */
    ThreadPool(size_t threads);

    /**
     * @brief Adds a new task to the thread pool for execution.
     *
     * @param task The task to be executed, encapsulated as a std::function.
     */
    void enqueue(std::function<void()> task);

    /**
     * @brief Destructs the ThreadPool, ensuring all threads are properly joined.
     */
    ~ThreadPool();

private:
    std::vector<std::thread> workers;          ///< Vector holding all worker threads.
    std::queue<std::function<void()>> tasks;   ///< Queue holding pending tasks.

    std::mutex queue_mutex;                    ///< Mutex to protect access to the task queue.
    std::condition_variable condition;         ///< Condition variable to notify worker threads.
    bool stop;                                 ///< Flag indicating whether the pool is stopping.
};
```

- **Description:**  
  Manages a pool of worker threads that execute tasks concurrently. Supports enqueueing of tasks which are then processed by the available threads.

- **Member Functions:**
  - `ThreadPool(size_t threads)`: Initializes the thread pool with the specified number of threads. Each thread runs a loop to process incoming tasks.
  - `enqueue(std::function<void()> task)`: Adds a new task to the task queue and notifies one of the waiting worker threads.
  - `~ThreadPool()`: Signals all threads to stop processing, notifies all worker threads, and joins them to ensure clean shutdown.

- **Usage:**  
  The thread pool is used to manage concurrent execution of SSH credential checks, allowing multiple authentication attempts to be performed in parallel without manually managing individual threads.

### Functions

#### `read_ips`

```cpp
bool read_ips(const std::string &filename, std::vector<std::string> &ips, log4cpp::Category &logger);
```

- **Description:**  
  Reads IP addresses from the specified file, removes whitespace, and populates the provided vector with valid IPs. Logs the outcome of the operation.

- **Parameters:**
  - `filename`: The path to the file containing IP addresses, one per line.
  - `ips`: A reference to a vector that will be populated with the read IP addresses.
  - `logger`: Reference to a `log4cpp::Category` object for logging messages.

- **Returns:**  
  `true` if the file was successfully read and IPs were extracted; `false` otherwise.

- **Workflow:**
  1. Opens the specified IPs file.
  2. Reads each line, trims whitespace, and adds non-empty lines to the `ips` vector.
  3. Logs the total number of IPs read.
  4. Handles and logs errors if the file cannot be opened.

- **Usage Example:**

  ```cpp
  std::vector<std::string> ips;
  if (!read_ips("data/ips.txt", ips, logger)) {
      logger.fatal("Failed to read IP addresses.");
      return 1;
  }
  ```

#### `read_usernames_passwords`

```cpp
bool read_usernames_passwords(const std::string &user_file, const std::string &pass_file,
                               std::vector<std::string> &usernames, std::vector<std::string> &passwords,
                               log4cpp::Category &logger);
```

- **Description:**  
  Reads usernames and passwords from their respective files, cleans them by removing whitespace, and populates the provided vectors. Ensures that the number of usernames matches the number of passwords and logs any discrepancies.

- **Parameters:**
  - `user_file`: The path to the file containing usernames, one per line.
  - `pass_file`: The path to the file containing passwords, one per line.
  - `usernames`: Reference to a vector that will be populated with the read usernames.
  - `passwords`: Reference to a vector that will be populated with the read passwords.
  - `logger`: Reference to a `log4cpp::Category` object for logging messages.

- **Returns:**  
  `true` if both files were successfully read and data was extracted; `false` otherwise.

- **Workflow:**
  1. Opens the usernames and passwords files.
  2. Reads corresponding lines from both files, trims whitespace, and adds non-empty entries to the `usernames` and `passwords` vectors.
  3. Checks if the number of usernames matches the number of passwords.
  4. Logs the total number of entries read and any warnings regarding mismatched counts.
  5. Handles and logs errors if any file cannot be opened.

- **Usage Example:**

  ```cpp
  std::vector<std::string> usernames;
  std::vector<std::string> passwords;
  if (!read_usernames_passwords("data/usernames.txt", "data/passwords.txt", usernames, passwords, logger)) {
      logger.fatal("Failed to read usernames and passwords.");
      return 1;
  }
  ```

#### `parse_ports`

```cpp
bool parse_ports(const std::string &port_str, std::vector<int> &ports, log4cpp::Category &logger);
```

- **Description:**  
  Parses a string containing port numbers and ranges (e.g., "22,2222,22-2020"), validates them, removes duplicates, and populates the provided vector with unique port numbers. Logs any invalid formats or out-of-range ports.

- **Parameters:**
  - `port_str`: The string containing ports and/or port ranges, separated by commas.
  - `ports`: Reference to a vector that will be populated with the parsed port numbers.
  - `logger`: Reference to a `log4cpp::Category` object for logging messages.

- **Returns:**  
  `true` if parsing was successful; `false` otherwise.

- **Workflow:**
  1. Splits the `port_str` by commas to extract individual ports or ranges.
  2. For each token:
     - If a dash (`-`) is present, interprets it as a range and adds all ports within that range.
     - If no dash is present, interprets it as a single port.
  3. Validates that each port is within the range 1-65535.
  4. Removes duplicate ports and sorts the list.
  5. Logs the total number of unique ports parsed and any warnings about invalid formats or ranges.

- **Usage Example:**

  ```cpp
  std::vector<int> ports;
  if (!parse_ports("22,2222,22-2020", ports, logger)) {
      logger.fatal("Failed to parse ports.");
      return 1;
  }
  ```

#### `read_user_pass`

```cpp
bool read_user_pass(const std::string &user_file, const std::string &pass_file,
                   std::vector<std::string> &usernames, std::vector<std::string> &passwords,
                   log4cpp::Category &logger);
```

- **Description:**  
  A wrapper function that calls `read_usernames_passwords` to read usernames and passwords from specified files. Simplifies the interface for reading credentials.

- **Parameters:**
  - `user_file`: The path to the file containing usernames.
  - `pass_file`: The path to the file containing passwords.
  - `usernames`: Reference to a vector that will be populated with the read usernames.
  - `passwords`: Reference to a vector that will be populated with the read passwords.
  - `logger`: Reference to a `log4cpp::Category` object for logging messages.

- **Returns:**  
  `true` if reading was successful; `false` otherwise.

- **Usage Example:**

  ```cpp
  std::vector<std::string> usernames;
  std::vector<std::string> passwords;
  if (!read_user_pass("data/usernames.txt", "data/passwords.txt", usernames, passwords, logger)) {
      logger.fatal("Failed to read user and password files.");
      return 1;
  }
  ```

#### `setup_logging`

```cpp
void setup_logging(bool is_debug);
```

- **Description:**  
  Configures the logging system using `log4cpp`. Sets up appenders for both file and console outputs and adjusts logging levels based on whether the application is running in debug mode.

- **Parameters:**
  - `is_debug`: A boolean flag indicating whether debug mode is enabled. If `true`, sets the logging level to `DEBUG`; otherwise, sets it to `INFO`.

- **Workflow:**
  1. Creates an `OstreamAppender` for file logging, directing output to `ssh_checker.log`.
  2. Defines a `PatternLayout` for formatting log messages with timestamps, priority levels, categories, and messages.
  3. Creates an `OstreamAppender` for console logging, directing output to `std::cout`.
  4. Applies the same `PatternLayout` to the console appender.
  5. Sets the root logging category's priority level based on the `is_debug` flag.
  6. Adds both file and console appenders to the root category.

- **Usage Example:**

  ```cpp
  bool debug_mode = true;
  setup_logging(debug_mode);
  log4cpp::Category& logger = log4cpp::Category::getRoot();
  ```

- **Example Log Messages:**

  - **Debug Mode:**
    ```
    2024-04-27 12:00:00 [DEBUG] ssh_checker: Detailed debug information here.
    ```
  
  - **Release Mode:**
    ```
    2024-04-27 12:00:00 [INFO] ssh_checker: General information here.
    ```

#### `check_credentials`

```cpp
bool check_credentials(const Credential &cred, int timeout, log4cpp::Category &logger);
```

- **Description:**  
  Attempts to authenticate to an SSH server using the provided credentials. Configures the SSH session with specified options, connects to the server, verifies the server's known host key, and performs password-based authentication. Logs all steps and outcomes of the authentication process.

- **Parameters:**
  - `cred`: A `Credential` structure containing the username, password, IP address, and port for the SSH connection.
  - `timeout`: The connection timeout in seconds.
  - `logger`: Reference to a `log4cpp::Category` object for logging messages.

- **Returns:**  
  `true` if authentication is successful; `false` otherwise.

- **Workflow:**
  1. **Session Initialization:**
     - Creates an `SSHSession` object to manage the SSH session lifecycle.
     - Retrieves the underlying `ssh_session` pointer.
  
  2. **Session Configuration:**
     - Sets the target host's IP address and port.
     - Configures the SSH username.
     - Sets the connection timeout.
     - Enables SSH2 protocol and disables SSH1.
     - Enforces strict host key checking for security.
     - Specifies algorithms for key exchange, ciphers, and HMAC to enhance security.
  
  3. **Connection Attempt:**
     - Attempts to connect to the SSH server.
     - Logs success or failure of the connection attempt.
  
  4. **Host Key Verification:**
     - Checks if the server's host key is known and trusted.
     - Logs any discrepancies or issues with the host key.
  
  5. **Authentication:**
     - Attempts password-based authentication using the provided credentials.
     - Logs the outcome of the authentication attempt.
  
  6. **Exception Handling:**
     - Catches and logs any exceptions that occur during the process.
  
- **Usage Example:**

  ```cpp
  Credential cred = {"user1", "password1", "192.168.1.10", 22};
  int timeout = 15;
  if (check_credentials(cred, timeout, logger)) {
      std::cout << "Authentication successful for " << cred.username << "@" << cred.ip << std::endl;
  } else {
      std::cout << "Authentication failed for " << cred.username << "@" << cred.ip << std::endl;
  }
  ```

- **Example Log Messages:**
  
  - **Successful Connection and Authentication:**
    ```
    2024-04-27 12:00:01 [DEBUG] ssh_checker: Настроены параметры SSH-сессии для 192.168.1.10:22
    2024-04-27 12:00:01 [DEBUG] ssh_checker: Подключение к 192.168.1.10 успешно.
    2024-04-27 12:00:01 [DEBUG] ssh_checker: Known_hosts проверен для 192.168.1.10.
    2024-04-27 12:00:01 [INFO] ssh_checker: Успешная аутентификация: user1@192.168.1.10:22
    ```
  
  - **Failed Connection:**
    ```
    2024-04-27 12:00:01 [DEBUG] ssh_checker: Настроены параметры SSH-сессии для 192.168.1.10:22
    2024-04-27 12:00:01 [ERROR] ssh_checker: Ошибка подключения к 192.168.1.10: Connection timed out
    ```
  
  - **Failed Authentication:**
    ```
    2024-04-27 12:00:01 [DEBUG] ssh_checker: Настроены параметры SSH-сессии для 192.168.1.10:22
    2024-04-27 12:00:01 [DEBUG] ssh_checker: Подключение к 192.168.1.10 успешно.
    2024-04-27 12:00:01 [DEBUG] ssh_checker: Known_hosts проверен для 192.168.1.10.
    2024-04-27 12:00:01 [WARN] ssh_checker: Неудачная аутентификация для user1@192.168.1.10:22 - Authentication failed
    ```

## Logging

SSH Checker utilizes `log4cpp` for logging, supporting multiple logging levels:

- **DEBUG:** Detailed information for debugging purposes. Includes verbose messages about internal operations, configurations, and state changes.
- **INFO:** General information about the application's operations. Logs high-level events such as the start and end of processes, successful authentications, and configuration details.
- **WARN:** Warnings about potential issues that do not halt the application. Examples include mismatched counts of usernames and passwords, invalid port formats, or unimplemented features.
- **ERROR:** Errors that occurred during execution but do not necessarily require immediate termination. Examples include failed connections or authentication attempts.
- **FATAL:** Critical errors leading to application termination. These are severe issues that prevent the application from continuing to operate correctly.

### Log Outputs

- **Console Logging:**  
  All log messages are output to the console (`std::cout`), allowing real-time monitoring of the application's progress and issues.

- **File Logging:**  
  Log messages are also written to a log file named `ssh_checker.log`. This file serves as a persistent record of all activities, useful for post-execution analysis and auditing.

### Log Message Format

Logs are formatted to include the timestamp, priority level, category, and the actual message:

```
YYYY-MM-DD HH:MM:SS [PRIORITY] category: message
```

**Example:**

```
2024-04-27 12:00:00 [INFO] ssh_checker: Запуск SSH Checker
```

### Adjusting Logging Levels

The verbosity of logging can be adjusted by switching between `Debug` and `Release` build modes:

- **Debug Mode:**  
  Enables `DEBUG` level logging, providing the most detailed information for troubleshooting and development.

- **Release Mode:**  
  Sets the logging level to `INFO`, focusing on essential operational messages and reducing log clutter.