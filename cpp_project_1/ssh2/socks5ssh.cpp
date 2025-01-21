// sw.cpp

#include <boost/asio.hpp>
#include <iostream>
#include <memory>
#include <array>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp> // Include nlohmann/json library
//#define LIBSSH_STATIC 1
#include <libssh/libssh.h>    // Include libssh

using boost::asio::ip::tcp;
using json = nlohmann::json;

// Logger class for thread-safe logging
class Logger {
public:
    template<typename... Args>
    static void log(Args... args) {
        std::lock_guard<std::mutex> lock(mutex_);
        (std::cout << ... << args) << std::endl;
    }

    template<typename... Args>
    static void error(Args... args) {
        std::lock_guard<std::mutex> lock(mutex_);
        (std::cerr << ... << args) << std::endl;
    }

private:
    static std::mutex mutex_;
};

std::mutex Logger::mutex_;

// Structure to hold tunnel configuration
struct TunnelConfig {
    std::string name;
    std::string host;
    int port;
    std::string username;
    std::string password;
    unsigned short local_port;
    // Additional fields can be added as needed
};

// SSHManager class for managing the SSH session
class SSHManager {
public:
    SSHManager(const TunnelConfig& config)
        : config_(config), reconnecting_(false),
          verbosity_(SSH_LOG_FUNCTIONS),
          timeout_(5),
          ciphers_("^aes128-ctr,aes256-ctr,aes192-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,blowfish-cbc,arcfour,cast128-cbc,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com"),
          key_exchange_("^diffie-hellman-group-exchange-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1"),
          macs_("^hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1,hmac-sha2-512,hmac-sha1-96,hmac-md5-96,umac-64@openssh.com,umac-128@openssh.com"),
          hostkeys_("ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ssh-ed25519"),
          compression_("none"),
          strict_host_key_checking_(0), // Disable host key checking
          process_config_(0) // Disable processing of SSH configuration files
    {
        initialize();
    }

    ~SSHManager() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ssh_session_) {
            ssh_disconnect(ssh_session_);
            ssh_free(ssh_session_);
            ssh_session_ = nullptr;
            Logger::log(config_.name, ": SSH session closed.");
        }
    }

    // Initialize the SSH session
    bool initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ssh_session_) {
            ssh_disconnect(ssh_session_);
            ssh_free(ssh_session_);
            ssh_session_ = nullptr;
        }

        ssh_session_ = ssh_new();
        if (ssh_session_ == nullptr) {
            Logger::error(config_.name, ": Failed to create SSH session.");
            return false;
        }

        int rc;

        // Disable processing of SSH configuration files
        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_PROCESS_CONFIG, &process_config_);
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_PROCESS_CONFIG: ", ssh_get_error(ssh_session_));
            return false;
        }

        // Set SSH options
        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_HOST, config_.host.c_str());
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_HOST: ", ssh_get_error(ssh_session_));
            return false;
        }

        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_PORT, &config_.port);
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_PORT: ", ssh_get_error(ssh_session_));
            return false;
        }

        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_USER, config_.username.c_str());
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_USER: ", ssh_get_error(ssh_session_));
            return false;
        }

        // Disable host key checking
        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict_host_key_checking_);
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_STRICTHOSTKEYCHECK: ", ssh_get_error(ssh_session_));
            return false;
        }

        // Set known hosts file to empty string to ignore known hosts
      //  const char* known_hosts = "";
      //  rc = ssh_options_set(ssh_session_, SSH_OPTIONS_KNOWNHOSTS, known_hosts);
      //  if (rc != SSH_OK) {
     //       Logger::error(config_.name, ": Error setting SSH_OPTIONS_KNOWNHOSTS: ", ssh_get_error(ssh_session_));
      //      return false;
     //   }

        // Set logging verbosity
        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_LOG_VERBOSITY, &verbosity_);
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_LOG_VERBOSITY: ", ssh_get_error(ssh_session_));
            return false;
        }

        // Set timeout
        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_TIMEOUT, &timeout_);
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_TIMEOUT: ", ssh_get_error(ssh_session_));
            return false;
        }


        // Set SSH algorithms
        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_CIPHERS_C_S, ciphers_.c_str());
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_CIPHERS_C_S: ", ssh_get_error(ssh_session_));
            return false;
        }

        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_KEY_EXCHANGE, key_exchange_.c_str());
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_KEY_EXCHANGE: ", ssh_get_error(ssh_session_));
            return false;
        }

        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_HMAC_C_S, macs_.c_str());
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_HMAC_C_S: ", ssh_get_error(ssh_session_));
            return false;
        }

        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_HMAC_S_C, macs_.c_str());
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_HMAC_S_C: ", ssh_get_error(ssh_session_));
            return false;
        }



        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_HOSTKEYS, hostkeys_.c_str());
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_HOSTKEYS: ", ssh_get_error(ssh_session_));
            return false;
        }

        rc = ssh_options_set(ssh_session_, SSH_OPTIONS_COMPRESSION, compression_.c_str());
        if (rc != SSH_OK) {
            Logger::error(config_.name, ": Error setting SSH_OPTIONS_COMPRESSION: ", ssh_get_error(ssh_session_));
            return false;
        }

        // Connect to SSH server
        if (ssh_connect(ssh_session_) != SSH_OK) {
            Logger::error(config_.name, ": SSH connection error: ", ssh_get_error(ssh_session_));
            ssh_free(ssh_session_);
            ssh_session_ = nullptr;
            return false;
        }

        // Authenticate
        if (ssh_userauth_password(ssh_session_, nullptr, config_.password.c_str()) != SSH_AUTH_SUCCESS) {
            Logger::error(config_.name, ": SSH authentication error: ", ssh_get_error(ssh_session_));
            ssh_disconnect(ssh_session_);
            ssh_free(ssh_session_);
            ssh_session_ = nullptr;
            return false;
        }

        Logger::log(config_.name, ": SSH session established for ", config_.username, "@", config_.host, ":", config_.port);
        return true;
    }

    // Get an SSH channel
    ssh_channel get_channel(const std::string& target_address, int target_port) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!ssh_session_) {
            Logger::error(config_.name, ": SSH session not established.");
            return nullptr;
        }

        ssh_channel channel = ssh_channel_new(ssh_session_);
        if (channel == nullptr) {
            Logger::error(config_.name, ": Failed to create SSH channel.");
            return nullptr;
        }

        // Use ssh_channel_open_forward to create the channel
        if (ssh_channel_open_forward(channel, target_address.c_str(), target_port, "127.0.0.1", 0) != SSH_OK) {
            Logger::error(config_.name, ": Failed to open SSH channel: ", ssh_get_error(ssh_session_));
            ssh_channel_free(channel);
            return nullptr;
        }

        Logger::log(config_.name, ": SSH channel successfully opened to ", target_address, ":", target_port);

        active_channels_++; // Increase active channel count

        return channel;
    }

    // Check if the SSH session is connected
    bool is_connected() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ssh_session_) return false;
        return ssh_is_connected(ssh_session_);
    }

    // Reconnect the SSH session
    bool reconnect() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (reconnecting_) {
            // Already attempting to reconnect
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            return is_connected();
        }

        if (active_channels_ > 0) {
            Logger::error(config_.name, ": Cannot reconnect while there are ", active_channels_, " active channels.");
            return false;
        }

        reconnecting_ = true;
        lock.unlock();

        Logger::log(config_.name, ": Attempting to reconnect to SSH server...");

        bool success = initialize();

        lock.lock();
        reconnecting_ = false;
        lock.unlock();

        if (success) {
            Logger::log(config_.name, ": Successfully reconnected to SSH server.");
        } else {
            Logger::error(config_.name, ": Failed to reconnect to SSH server.");
        }

        return success;
    }

    // Get the SSH error message
    std::string get_error_message() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ssh_session_)
            return ssh_get_error(ssh_session_);
        else
            return "No SSH session.";
    }

    // Decrease the active channel count
    void decrement_channel_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_channels_ > 0)
            active_channels_--;
    }

private:
    TunnelConfig config_;
    ssh_session ssh_session_ = nullptr;
    std::mutex mutex_;

    size_t active_channels_ = 0; // Active channel count
    bool reconnecting_;

    // SSH options
    int verbosity_;
    long timeout_;
    std::string ciphers_;
    std::string key_exchange_;
    std::string macs_;
    std::string hostkeys_;
    std::string compression_;
    int strict_host_key_checking_;
    int process_config_;
};


// Класс Session для обработки одного клиентского подключения
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket client_socket, boost::asio::io_context& io_context,
            std::shared_ptr<SSHManager> ssh_manager, const std::string& tunnel_name)
        : client_socket_(std::move(client_socket)),
          io_context_(io_context),
          strand_(boost::asio::make_strand(io_context)),
          ssh_manager_(ssh_manager),
          tunnel_name_(tunnel_name)
    {}

    void start() {
        auto self = shared_from_this();
        boost::asio::post(strand_,
            [this, self]() {
                handle_handshake();
            }
        );
    }

private:
    // Шаг 1: Обработка рукопожатия SOCKS5
    void handle_handshake() {
        auto self = shared_from_this();
        boost::asio::async_read(client_socket_,
            boost::asio::buffer(handshake_buffer_),
            boost::asio::transfer_exactly(2),
            boost::asio::bind_executor(strand_,
                [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec && bytes_transferred == 2) {
                        unsigned char version = handshake_buffer_[0];
                        unsigned char nmethods = handshake_buffer_[1];

                        if (version != 0x05) {
                            Logger::error(tunnel_name_, ": Неподдерживаемая версия SOCKS: ", static_cast<int>(version));
                            do_close();
                            return;
                        }

                        // Чтение методов аутентификации
                        methods_buffer_.resize(nmethods);
                        boost::asio::async_read(client_socket_,
                            boost::asio::buffer(methods_buffer_),
                            boost::asio::transfer_exactly(nmethods),
                            boost::asio::bind_executor(strand_,
                                [this, self, nmethods](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                    if (!ec && bytes_transferred == nmethods) {
                                        bool no_auth = false;
                                        for (int i = 0; i < nmethods; ++i) {
                                            if (methods_buffer_[i] == 0x00) { // Без аутентификации
                                                no_auth = true;
                                                break;
                                            }
                                        }

                                        if (no_auth) {
                                            // Отправка ответа: версия 5, метод 0 (без аутентификации)
                                            unsigned char response[2] = {0x05, 0x00};
                                            boost::asio::async_write(client_socket_,
                                                boost::asio::buffer(response, 2),
                                                boost::asio::bind_executor(strand_,
                                                    [this, self](const boost::system::error_code& ec, std::size_t) {
                                                        if (!ec) {
                                                            handle_request();
                                                        } else {
                                                            Logger::error(tunnel_name_, ": Ошибка отправки ответа рукопожатия: ", ec.message());
                                                            do_close();
                                                        }
                                                    }
                                                )
                                            );
                                        }
                                        else {
                                            // Нет поддерживаемых методов аутентификации
                                            unsigned char response[2] = {0x05, 0xFF};
                                            boost::asio::async_write(client_socket_,
                                                boost::asio::buffer(response, 2),
                                                boost::asio::bind_executor(strand_,
                                                    [this, self](const boost::system::error_code& ec, std::size_t) {
                                                        if (ec) {
                                                            Logger::error(tunnel_name_, ": Ошибка отправки ответа об ошибке рукопожатия: ", ec.message());
                                                        }
                                                        do_close();
                                                    }
                                                )
                                            );
                                        }
                                    }
                                    else {
                                        Logger::error(tunnel_name_, ": Ошибка чтения методов аутентификации: ", ec.message());
                                        do_close();
                                    }
                                }
                            )
                        );
                    }
                    else {
                        Logger::error(tunnel_name_, ": Ошибка чтения рукопожатия: ", ec.message());
                        do_close();
                    }
                }
            )
        );
    }

    // Шаг 2: Обработка запроса SOCKS5
    void handle_request() {
        auto self = shared_from_this();
        boost::asio::async_read(client_socket_,
            boost::asio::buffer(request_buffer_),
            boost::asio::transfer_exactly(4),
            boost::asio::bind_executor(strand_,
                [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec && bytes_transferred == 4) {
                        unsigned char version = request_buffer_[0];
                        unsigned char cmd = request_buffer_[1];
                        unsigned char reserved = request_buffer_[2];
                        unsigned char address_type = request_buffer_[3];

                        if (version != 0x05) {
                            Logger::error(tunnel_name_, ": Неподдерживаемая версия SOCKS в запросе: ", static_cast<int>(version));
                            send_reply(0x01); // Общая ошибка
                            return;
                        }

                        if (cmd != 0x01) { // Поддерживается только команда CONNECT
                            Logger::error(tunnel_name_, ": Неподдерживаемая команда SOCKS: ", static_cast<int>(cmd));
                            send_reply(0x07); // Команда не поддерживается
                            return;
                        }

                        // Определение типа адреса и чтение соответствующих данных
                        if (address_type == 0x01) { // IPv4
                            boost::asio::async_read(client_socket_,
                                boost::asio::buffer(ipv4_buffer_),
                                boost::asio::transfer_exactly(6), // IP (4 байта) + порт (2 байта)
                                boost::asio::bind_executor(strand_,
                                    [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                        if (!ec && bytes_transferred == 6) {
                                            // Конвертация IP-адреса из байтов в строку
                                            std::ostringstream oss;
                                            oss << static_cast<int>(ipv4_buffer_[0]) << "."
                                                << static_cast<int>(ipv4_buffer_[1]) << "."
                                                << static_cast<int>(ipv4_buffer_[2]) << "."
                                                << static_cast<int>(ipv4_buffer_[3]);
                                            target_address_ = oss.str();
                                            target_port_ = (static_cast<int>(ipv4_buffer_[4]) << 8) | static_cast<int>(ipv4_buffer_[5]);
                                            Logger::log(tunnel_name_, ": Запрос на подключение к ", target_address_, ":", target_port_);
                                            connect_to_target_via_ssh();
                                        }
                                        else {
                                            Logger::error(tunnel_name_, ": Ошибка чтения IPv4 адреса и порта: ", ec.message());
                                            send_reply(0x01); // Общая ошибка
                                        }
                                    }
                                )
                            );
                        }
                        else if (address_type == 0x03) { // Доменное имя
                            // Чтение длины доменного имени
                            boost::asio::async_read(client_socket_,
                                boost::asio::buffer(domain_length_buffer_),
                                boost::asio::transfer_exactly(1),
                                boost::asio::bind_executor(strand_,
                                    [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                        if (!ec && bytes_transferred == 1) {
                                            unsigned char domain_length = domain_length_buffer_[0];
                                            if (domain_length == 0) {
                                                Logger::error(tunnel_name_, ": Длина доменного имени не может быть нулевой.");
                                                send_reply(0x01); // Общая ошибка
                                                return;
                                            }

                                            // Чтение доменного имени
                                            domain_name_buffer_.resize(domain_length);
                                            boost::asio::async_read(client_socket_,
                                                boost::asio::buffer(domain_name_buffer_),
                                                boost::asio::transfer_exactly(domain_length),
                                                boost::asio::bind_executor(strand_,
                                                    [this, self, domain_length](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                                        if (!ec && bytes_transferred == domain_length) {
                                                            target_address_ = std::string(domain_name_buffer_.begin(), domain_name_buffer_.end());

                                                            // Чтение порта
                                                            boost::asio::async_read(client_socket_,
                                                                boost::asio::buffer(port_buffer_),
                                                                boost::asio::transfer_exactly(2),
                                                                boost::asio::bind_executor(strand_,
                                                                    [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                                                        if (!ec && bytes_transferred == 2) {
                                                                            target_port_ = (static_cast<int>(port_buffer_[0]) << 8) | static_cast<int>(port_buffer_[1]);
                                                                            Logger::log(tunnel_name_, ": Запрос на подключение к ", target_address_, ":", target_port_);
                                                                            connect_to_target_via_ssh();
                                                                        }
                                                                        else {
                                                                            Logger::error(tunnel_name_, ": Ошибка чтения порта: ", ec.message());
                                                                            send_reply(0x01); // Общая ошибка
                                                                        }
                                                                    }
                                                                )
                                                            );
                                                        }
                                                        else {
                                                            Logger::error(tunnel_name_, ": Ошибка чтения доменного имени: ", ec.message());
                                                            send_reply(0x01); // Общая ошибка
                                                        }
                                                    }
                                                )
                                            );
                                        }
                                        else {
                                            Logger::error(tunnel_name_, ": Ошибка чтения длины доменного имени: ", ec.message());
                                            send_reply(0x01); // Общая ошибка
                                        }
                                    }
                                )
                            );
                        }
                        else { // Неподдерживаемый тип адреса
                            Logger::error(tunnel_name_, ": Неподдерживаемый тип адреса: ", static_cast<int>(address_type));
                            send_reply(0x08); // Тип адреса не поддерживается
                            return;
                        }
                    }
                    else {
                        Logger::error(tunnel_name_, ": Ошибка чтения запроса: ", ec.message());
                        do_close();
                    }
                }
            )
        );
    }

    // Подключение к целевому серверу через SSH
    void connect_to_target_via_ssh() {
        auto self = shared_from_this();

        // Получение SSH-канала
        ssh_channel channel = ssh_manager_->get_channel(target_address_, target_port_);
        if (channel == nullptr) {
            Logger::error(tunnel_name_, ": Не удалось открыть SSH-канал. Пытаемся переподключиться.");
            if (ssh_manager_->reconnect()) {
                channel = ssh_manager_->get_channel(target_address_, target_port_);
                if (channel == nullptr) {
                    Logger::error(tunnel_name_, ": Переподключение не удалось. Отправляем ошибку подключения клиенту.");
                    send_reply(0x05); // Подключение отказано
                    return;
                }
            }
            else {
                Logger::error(tunnel_name_, ": Переподключение не удалось. Отправляем ошибку подключения клиенту.");
                send_reply(0x05); // Подключение отказано
                return;
            }
        }

        // Сохранение SSH-канала для передачи данных
        ssh_channel_ = channel;

        // Отправка успешного ответа клиенту
        send_reply(0x00);
    }

    // Отправка ответа SOCKS5 клиенту
    void send_reply(unsigned char reply_code) {
        std::vector<unsigned char> response;
        response.push_back(0x05); // Версия SOCKS
        response.push_back(reply_code); // Код ответа
        response.push_back(0x00); // Зарезервировано

        if (reply_code == 0x00) { // Успех
            // Заполнение BND.ADDR и BND.PORT локальным конечным адресом
            boost::system::error_code ec;
            tcp::endpoint local_endpoint = client_socket_.local_endpoint(ec);
            if (!ec) {
                if (local_endpoint.address().is_v4()) {
                    response.push_back(0x01); // IPv4
                    auto bytes = local_endpoint.address().to_v4().to_bytes();
                    response.insert(response.end(), bytes.begin(), bytes.end());
                }
                else {
                    // IPv6 не поддерживается в этой версии, но добавлено для совместимости
                    response.push_back(0x01); // IPv4
                    response.insert(response.end(), {0x00, 0x00, 0x00, 0x00});
                }
                unsigned short port = local_endpoint.port();
                response.push_back(static_cast<unsigned char>((port >> 8) & 0xFF));
                response.push_back(static_cast<unsigned char>(port & 0xFF));
            }
            else {
                // Если невозможно получить локальный конечный адрес, заполнение нулями
                response.push_back(0x01); // IPv4
                response.insert(response.end(), {0x00, 0x00, 0x00, 0x00});
                response.push_back(0x00);
                response.push_back(0x00);
            }
        }
        else { // Ошибка
            response.push_back(0x01); // IPv4
            response.insert(response.end(), {0x00, 0x00, 0x00, 0x00});
            response.push_back(0x00);
            response.push_back(0x00);
        }

        auto self = shared_from_this();
        boost::asio::async_write(client_socket_,
            boost::asio::buffer(response),
            boost::asio::bind_executor(strand_,
                [this, self, reply_code](const boost::system::error_code& ec, std::size_t) {
                    if (!ec) {
                        if (reply_code == 0x00) {
                            // Успешное подключение, начало передачи данных
                            start_relay();
                        }
                        else {
                            // Если произошла ошибка, закрытие соединения
                            do_close();
                        }
                    }
                    else {
                        Logger::error(tunnel_name_, ": Ошибка отправки ответа: ", ec.message());
                        do_close();
                    }
                }
            )
        );
    }

    // Начало двунаправленной передачи данных между клиентом и SSH-каналом
    void start_relay() {
        relay_client_to_ssh();
        relay_ssh_to_client();
    }

    // Передача данных от клиента к SSH-каналу
    void relay_client_to_ssh() {
        auto self = shared_from_this();
        boost::asio::async_read(client_socket_,
            boost::asio::buffer(client_buffer_),
            boost::asio::transfer_at_least(1),
            boost::asio::bind_executor(strand_,
                [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec) {
                        // Запись данных в SSH-канал
                        int bytes_written = ssh_channel_write(ssh_channel_, reinterpret_cast<char*>(client_buffer_.data()), bytes_transferred);
                        if (bytes_written < 0) {
                            Logger::error(tunnel_name_, ": Ошибка записи в SSH-канал: ", ssh_manager_->get_error_message());
                            do_close();
                            return;
                        }

                        // Продолжение чтения от клиента
                        relay_client_to_ssh();
                    }
                    else {
                        if (ec != boost::asio::error::eof) {
                            Logger::error(tunnel_name_, ": Ошибка чтения от клиента: ", ec.message());
                        }
                        do_close();
                    }
                }
            )
        );
    }

    // Передача данных от SSH-канала к клиенту
    void relay_ssh_to_client() {
        auto self = shared_from_this();

        // Проверка, что SSH-канал все еще валиден
        if (!ssh_channel_ || ssh_channel_is_closed(ssh_channel_)) {
            Logger::error(tunnel_name_, ": SSH-канал закрыт или недействителен.");
            do_close();
            return;
        }

        // Чтение данных из SSH-канала
        int bytes_read = ssh_channel_read_nonblocking(ssh_channel_,
                                                      reinterpret_cast<char*>(server_buffer_.data()),
                                                      server_buffer_.size(),
                                                      0);
        if (bytes_read > 0) {
            boost::asio::async_write(client_socket_,
                boost::asio::buffer(server_buffer_.data(), bytes_read),
                boost::asio::bind_executor(strand_,
                    [this, self](const boost::system::error_code& ec, std::size_t) {
                        if (!ec) {
                            relay_ssh_to_client();
                        }
                        else {
                            Logger::error(tunnel_name_, ": Ошибка отправки данных от сервера к клиенту: ", ec.message());
                            do_close();
                        }
                    }
                )
            );
        }
        else if (bytes_read == 0) {
            // Нет доступных данных, ожидание и повторная попытка
            auto timer = std::make_shared<boost::asio::steady_timer>(io_context_, std::chrono::milliseconds(100));
            timer->async_wait(boost::asio::bind_executor(strand_,
                [this, self, timer](const boost::system::error_code& ec) {
                    if (!ec) {
                        relay_ssh_to_client();
                    }
                    else {
                        do_close();
                    }
                }
            ));
        }
        else { // bytes_read < 0 означает ошибку или EOF
            if (ssh_channel_is_eof(ssh_channel_)) {
                Logger::log(tunnel_name_, ": SSH-канал достиг конца файла (EOF).");
                do_close();
            }
            else {
                Logger::error(tunnel_name_, ": Ошибка чтения из SSH-канала: ", ssh_manager_->get_error_message());
                do_close();
            }
        }
    }

    // Закрытие соединений и освобождение ресурсов SSH
    void do_close() {
        auto self = shared_from_this();
        boost::asio::post(strand_,
            [this, self]() {
                boost::system::error_code ec;
                if (client_socket_.is_open()) {
                    client_socket_.shutdown(tcp::socket::shutdown_both, ec);
                    client_socket_.close(ec);
                    Logger::log(tunnel_name_, ": Соединение с клиентом закрыто.");
                }
                if (ssh_channel_) {
                    ssh_channel_send_eof(ssh_channel_);
                    ssh_channel_close(ssh_channel_);
                    ssh_channel_free(ssh_channel_);
                    ssh_channel_ = nullptr;
                    Logger::log(tunnel_name_, ": SSH-канал закрыт.");
                    ssh_manager_->decrement_channel_count(); // Уменьшение счетчика активных каналов
                }
            }
        );
    }

    // Членские переменные
    tcp::socket client_socket_;
    boost::asio::io_context& io_context_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;

    std::shared_ptr<SSHManager> ssh_manager_;
    std::string tunnel_name_;

    // Буферы данных
    std::array<unsigned char, 2> handshake_buffer_;
    std::vector<unsigned char> methods_buffer_;
    std::array<unsigned char, 4> request_buffer_;
    std::array<unsigned char, 6> ipv4_buffer_;
    std::array<unsigned char, 1> domain_length_buffer_;
    std::vector<unsigned char> domain_name_buffer_;
    std::array<unsigned char, 2> port_buffer_;
    std::array<unsigned char, 8192> client_buffer_;
    std::array<unsigned char, 8192> server_buffer_;

    // Целевой адрес и порт
    std::string target_address_;
    unsigned short target_port_;

    // SSH-канал
    ssh_channel ssh_channel_ = nullptr;
};

// Класс Socks5Proxy для прослушивания и принятия подключений
class Socks5Proxy {
public:
    Socks5Proxy(boost::asio::io_context& io_context, const TunnelConfig& config)
        : io_context_(io_context),
          acceptor_(io_context, tcp::endpoint(tcp::v4(), config.local_port)),
          ssh_manager_(std::make_shared<SSHManager>(config)),
          tunnel_name_(config.name)
    {}

    void start() {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](const boost::system::error_code& ec, tcp::socket socket) {
                if (!ec) {
                    try {
                        Logger::log(tunnel_name_, ": Принято подключение от ", socket.remote_endpoint());
                    }
                    catch (std::exception& e) {
                        Logger::error(tunnel_name_, ": Ошибка получения удаленного конечного адреса: ", e.what());
                    }
                    // Создание новой сессии с использованием SSHManager
                    std::make_shared<Session>(std::move(socket), io_context_, ssh_manager_, tunnel_name_)->start();
                }
                else {
                    Logger::error(tunnel_name_, ": Ошибка принятия подключения: ", ec.message());
                }
                do_accept();
            }
        );
    }

    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    std::shared_ptr<SSHManager> ssh_manager_;
    std::string tunnel_name_;
};

// Функция для чтения и парсинга JSON-конфига из файла
bool read_config(const std::string& file_path, std::vector<TunnelConfig>& tunnels) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        Logger::error("Не удалось открыть конфигурационный файл: ", file_path);
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    try {
        json j = json::parse(content);

        if (!j.is_array()) {
            Logger::error("Конфигурационный файл должен содержать массив туннелей.");
            return false;
        }

        for (const auto& item : j) {
            TunnelConfig config;

            // Валидация и извлечение обязательных полей
            if (!item.contains("name") || !item["name"].is_string()) {
                Logger::error("Туннель пропущен из-за отсутствия или неправильного поля 'name'.");
                continue;
            }
            config.name = item["name"].get<std::string>();

            if (!item.contains("host") || !item["host"].is_string()) {
                Logger::error(config.name, ": Пропущен из-за отсутствия или неправильного поля 'host'.");
                continue;
            }
            config.host = item["host"].get<std::string>();

            if (!item.contains("port") || !item["port"].is_number_integer()) {
                Logger::error(config.name, ": Пропущен из-за отсутствия или неправильного поля 'port'.");
                continue;
            }
            config.port = item["port"].get<int>();

            if (!item.contains("username") || !item["username"].is_string()) {
                Logger::error(config.name, ": Пропущен из-за отсутствия или неправильного поля 'username'.");
                continue;
            }
            config.username = item["username"].get<std::string>();

            if (!item.contains("password") || !item["password"].is_string()) {
                Logger::error(config.name, ": Пропущен из-за отсутствия или неправильного поля 'password'.");
                continue;
            }
            config.password = item["password"].get<std::string>();

            if (!item.contains("local_port") || !item["local_port"].is_number_integer()) {
                Logger::error(config.name, ": Пропущен из-за отсутствия или неправильного поля 'local_port'.");
                continue;
            }
            config.local_port = static_cast<unsigned short>(item["local_port"].get<int>());

            // Дополнительные поля могут быть обработаны здесь

            tunnels.push_back(config);
        }

        if (tunnels.empty()) {
            Logger::error("Конфигурационный файл не содержит валидных туннелей.");
            return false;
        }

    }
    catch (json::parse_error& e) {
        Logger::error("Ошибка парсинга JSON-конфига: ", e.what());
        return false;
    }

    return true;
}

// Главная функция
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Использование: " << argv[0] << " <путь_к_конфигурационному_файлу.json>" << std::endl;
        return 1;
    }

    std::string config_file = argv[1];
    std::vector<TunnelConfig> tunnels;

    if (!read_config(config_file, tunnels)) {
        return 1;
    }

    try {
        // Создание общего io_context для всех прокси
        boost::asio::io_context io_context;

        // Создание объекта work_guard для предотвращения выхода io_context из run до завершения работы
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard(io_context.get_executor());

        // Создание и запуск всех прокси-серверов
        std::vector<std::shared_ptr<Socks5Proxy>> proxies;
        for (const auto& tunnel : tunnels) {
            proxies.emplace_back(std::make_shared<Socks5Proxy>(io_context, tunnel));
            proxies.back()->start();
            Logger::log(tunnel.name, ": Прокси-сервер запущен на порту ", tunnel.local_port, ".");
        }

        // Определение размера пула потоков (например, количество доступных ядер)
        std::size_t thread_pool_size = std::thread::hardware_concurrency();
        if (thread_pool_size == 0) thread_pool_size = 4; // Значение по умолчанию, если невозможно определить

        // Создание пула потоков для обработки io_context
        std::vector<std::thread> threads;
        for (std::size_t i = 0; i < thread_pool_size; ++i) {
            threads.emplace_back([&io_context]() {
                io_context.run();
            });
        }

        Logger::log("Все прокси-серверы запущены. Используется пул потоков из ", thread_pool_size, " потоков.");

        // Ожидание завершения всех потоков
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

    }
    catch (std::exception& e) {
        Logger::error("Main: Исключение: ", e.what());
    }

    return 0;
}
