// ss.cpp

#include <boost/asio.hpp>
#include <iostream>
#include <memory>
#include <array>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <libssh/libssh.h> // Подключение libssh

using boost::asio::ip::tcp;

// Класс Logger для потокобезопасного вывода логов
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

// Класс SSHManager для управления SSH-сессией
class SSHManager {
public:
    SSHManager(const std::string& host, int port, const std::string& user, const std::string& password,
               int verbosity, long timeout,
               const std::string& ciphers_c_s,
               const std::string& key_exchange,
               const std::string& hmac_c_s,
               const std::string& hostkeys,
               const std::string& compression)
        : host_(host), port_(port), user_(user), password_(password),
          verbosity_(verbosity), timeout_(timeout),
          ciphers_c_s_(ciphers_c_s), key_exchange_(key_exchange),
          hmac_c_s_(hmac_c_s), hostkeys_(hostkeys),
          compression_(compression), reconnecting_(false)
    {
        initialize();
    }

    ~SSHManager() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ssh_session_) {
            ssh_disconnect(ssh_session_);
            ssh_free(ssh_session_);
            ssh_session_ = nullptr;
            Logger::log("SSHManager: SSH-сессия закрыта.");
        }
    }

    // Инициализация SSH-сессии
    bool initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ssh_session_) {
            ssh_disconnect(ssh_session_);
            ssh_free(ssh_session_);
            ssh_session_ = nullptr;
        }

        ssh_session_ = ssh_new();
        if (ssh_session_ == nullptr) {
            Logger::error("SSHManager: Не удалось создать SSH-сессию.");
            return false;
        }

        // Установка SSH-параметров
        ssh_options_set(ssh_session_, SSH_OPTIONS_HOST, host_.c_str());
        ssh_options_set(ssh_session_, SSH_OPTIONS_PORT, &port_);
        ssh_options_set(ssh_session_, SSH_OPTIONS_USER, user_.c_str());

        // Дополнительные SSH-параметры
        ssh_options_set(ssh_session_, SSH_OPTIONS_LOG_VERBOSITY, &verbosity_);
        ssh_options_set(ssh_session_, SSH_OPTIONS_TIMEOUT, &timeout_);
        ssh_options_set(ssh_session_, SSH_OPTIONS_CIPHERS_C_S, ciphers_c_s_.c_str());
        ssh_options_set(ssh_session_, SSH_OPTIONS_KEY_EXCHANGE, key_exchange_.c_str());
        ssh_options_set(ssh_session_, SSH_OPTIONS_HMAC_C_S, hmac_c_s_.c_str());
        ssh_options_set(ssh_session_, SSH_OPTIONS_HOSTKEYS, hostkeys_.c_str());
        ssh_options_set(ssh_session_, SSH_OPTIONS_COMPRESSION, compression_.c_str());

        // Подключение к SSH-серверу
        if (ssh_connect(ssh_session_) != SSH_OK) {
            Logger::error("SSHManager: Ошибка подключения SSH: ", ssh_get_error(ssh_session_));
            ssh_free(ssh_session_);
            ssh_session_ = nullptr;
            return false;
        }

        // Аутентификация
        if (ssh_userauth_password(ssh_session_, nullptr, password_.c_str()) != SSH_AUTH_SUCCESS) {
            Logger::error("SSHManager: Ошибка аутентификации SSH: ", ssh_get_error(ssh_session_));
            ssh_disconnect(ssh_session_);
            ssh_free(ssh_session_);
            ssh_session_ = nullptr;
            return false;
        }

        Logger::log("SSHManager: SSH-сессия установлена для ", user_, "@", host_, ":", port_);
        return true;
    }

    // Получение SSH-канала
    ssh_channel get_channel(const std::string& target_address, int target_port) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!ssh_session_) {
            Logger::error("SSHManager: SSH-сессия не установлена.");
            return nullptr;
        }

        ssh_channel channel = ssh_channel_new(ssh_session_);
        if (channel == nullptr) {
            Logger::error("SSHManager: Не удалось создать SSH-канал.");
            return nullptr;
        }

        if (ssh_channel_open_forward(channel, target_address.c_str(), target_port, "localhost", 0) != SSH_OK) {
            Logger::error("SSHManager: Не удалось открыть SSH-канал: ", ssh_get_error(ssh_session_));
            ssh_channel_free(channel);
            return nullptr;
        }

        Logger::log("SSHManager: SSH-канал успешно открыт для ", target_address, ":", target_port);
        
        active_channels_++; // Увеличение счетчика активных каналов

        return channel;
    }

    // Проверка соединения SSH-сессии
    bool is_connected() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ssh_session_) return false;
        return ssh_is_connected(ssh_session_);
    }

    // Переподключение SSH-сессии
    bool reconnect() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (reconnecting_) {
            // Уже выполняется попытка переподключения
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            return is_connected();
        }

        if (active_channels_ > 0) {
            Logger::error("SSHManager: Невозможно переподключиться, пока есть ", active_channels_, " активных каналов.");
            return false;
        }

        reconnecting_ = true;
        lock.unlock();

        Logger::log("SSHManager: Пытаемся переподключиться к SSH-серверу...");

        bool success = initialize();

        lock.lock();
        reconnecting_ = false;
        lock.unlock();

        if (success) {
            Logger::log("SSHManager: Успешно переподключились к SSH-серверу.");
        } else {
            Logger::error("SSHManager: Не удалось переподключиться к SSH-серверу.");
        }

        return success;
    }

    // Получение сообщения об ошибке SSH
    std::string get_error_message() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ssh_session_)
            return ssh_get_error(ssh_session_);
        else
            return "Нет SSH-сессии.";
    }

    // Уменьшение счетчика активных каналов
    void decrement_channel_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_channels_ > 0)
            active_channels_--;
    }

private:
    std::string host_;
    int port_;
    std::string user_;
    std::string password_;

    int verbosity_;
    long timeout_;
    std::string ciphers_c_s_;
    std::string key_exchange_;
    std::string hmac_c_s_;
    std::string hostkeys_;
    std::string compression_;

    ssh_session ssh_session_ = nullptr;
    std::mutex mutex_;

    size_t active_channels_ = 0; // Счетчик активных каналов
    bool reconnecting_;
};

// Класс Session для обработки одного клиентского подключения
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket client_socket, boost::asio::io_context& io_context,
            std::shared_ptr<SSHManager> ssh_manager)
        : client_socket_(std::move(client_socket)),
          io_context_(io_context),
          strand_(boost::asio::make_strand(io_context)),
          ssh_manager_(ssh_manager)
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
            boost::asio::buffer(handshake_buffer_, 2),
            boost::asio::bind_executor(strand_,
                [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec && bytes_transferred == 2) {
                        unsigned char version = handshake_buffer_[0];
                        unsigned char nmethods = handshake_buffer_[1];

                        if (version != 0x05) {
                            Logger::error("Неподдерживаемая версия SOCKS: ", static_cast<int>(version));
                            do_close();
                            return;
                        }

                        // Чтение методов аутентификации
                        methods_buffer_.resize(nmethods);
                        boost::asio::async_read(client_socket_,
                            boost::asio::buffer(methods_buffer_),
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
                                                            Logger::error("Ошибка отправки ответа рукопожатия: ", ec.message());
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
                                                            Logger::error("Ошибка отправки ответа об ошибке рукопожатия: ", ec.message());
                                                        }
                                                        do_close();
                                                    }
                                                )
                                            );
                                        }
                                    }
                                    else {
                                        Logger::error("Ошибка чтения методов аутентификации: ", ec.message());
                                        do_close();
                                    }
                                }
                            )
                        );
                    }
                    else {
                        Logger::error("Ошибка чтения рукопожатия: ", ec.message());
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
            boost::asio::buffer(request_buffer_, 4),
            boost::asio::bind_executor(strand_,
                [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec && bytes_transferred == 4) {
                        unsigned char version = request_buffer_[0];
                        unsigned char cmd = request_buffer_[1];
                        unsigned char reserved = request_buffer_[2];
                        unsigned char address_type = request_buffer_[3];

                        if (version != 0x05) {
                            Logger::error("Неподдерживаемая версия SOCKS в запросе: ", static_cast<int>(version));
                            send_reply(0x01); // Общая ошибка
                            return;
                        }

                        if (cmd != 0x01) { // Поддерживается только команда CONNECT
                            Logger::error("Неподдерживаемая команда SOCKS: ", static_cast<int>(cmd));
                            send_reply(0x07); // Команда не поддерживается
                            return;
                        }

                        // Определение типа адреса и чтение соответствующих данных
                        if (address_type == 0x01) { // IPv4
                            boost::asio::async_read(client_socket_,
                                boost::asio::buffer(ipv4_buffer_, 6), // IP (4 байта) + порт (2 байта)
                                boost::asio::bind_executor(strand_,
                                    [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                        if (!ec && bytes_transferred == 6) {
                                            boost::asio::ip::address_v4 addr_v4(
                                                std::array<unsigned char, 4>{
                                                    ipv4_buffer_[0],
                                                    ipv4_buffer_[1],
                                                    ipv4_buffer_[2],
                                                    ipv4_buffer_[3]
                                                }
                                            );
                                            target_address_ = addr_v4.to_string();
                                            target_port_ = (ipv4_buffer_[4] << 8) | ipv4_buffer_[5];
                                            Logger::log("Запрос на подключение к ", target_address_, ":", target_port_);
                                            connect_to_target_via_ssh();
                                        }
                                        else {
                                            Logger::error("Ошибка чтения IPv4 адреса и порта: ", ec.message());
                                            send_reply(0x01); // Общая ошибка
                                        }
                                    }
                                )
                            );
                        }
                        else if (address_type == 0x03) { // Доменное имя
                            // Чтение длины доменного имени
                            boost::asio::async_read(client_socket_,
                                boost::asio::buffer(domain_length_buffer_, 1),
                                boost::asio::bind_executor(strand_,
                                    [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                        if (!ec && bytes_transferred == 1) {
                                            unsigned char domain_length = domain_length_buffer_[0];
                                            if (domain_length == 0) {
                                                Logger::error("Длина доменного имени не может быть нулевой.");
                                                send_reply(0x01); // Общая ошибка
                                                return;
                                            }

                                            // Чтение доменного имени
                                            domain_name_buffer_.resize(domain_length);
                                            boost::asio::async_read(client_socket_,
                                                boost::asio::buffer(domain_name_buffer_),
                                                boost::asio::bind_executor(strand_,
                                                    [this, self, domain_length](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                                        if (!ec && bytes_transferred == domain_length) {
                                                            target_address_ = std::string(domain_name_buffer_.begin(), domain_name_buffer_.end());

                                                            // Чтение порта
                                                            boost::asio::async_read(client_socket_,
                                                                boost::asio::buffer(port_buffer_, 2),
                                                                boost::asio::bind_executor(strand_,
                                                                    [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                                                        if (!ec && bytes_transferred == 2) {
                                                                            target_port_ = (port_buffer_[0] << 8) | port_buffer_[1];
                                                                            Logger::log("Запрос на подключение к ", target_address_, ":", target_port_);
                                                                            connect_to_target_via_ssh();
                                                                        }
                                                                        else {
                                                                            Logger::error("Ошибка чтения порта: ", ec.message());
                                                                            send_reply(0x01); // Общая ошибка
                                                                        }
                                                                    }
                                                                )
                                                            );
                                                        }
                                                        else {
                                                            Logger::error("Ошибка чтения доменного имени: ", ec.message());
                                                            send_reply(0x01); // Общая ошибка
                                                        }
                                                    }
                                                )
                                            );
                                        }
                                        else {
                                            Logger::error("Ошибка чтения длины доменного имени: ", ec.message());
                                            send_reply(0x01); // Общая ошибка
                                        }
                                    }
                                )
                            );
                        }
                        else { // Неподдерживаемый тип адреса
                            Logger::error("Неподдерживаемый тип адреса: ", static_cast<int>(address_type));
                            send_reply(0x08); // Тип адреса не поддерживается
                            return;
                        }
                    }
                    else {
                        Logger::error("Ошибка чтения запроса: ", ec.message());
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
            Logger::error("Session: Не удалось открыть SSH-канал. Пытаемся переподключиться.");
            if (ssh_manager_->reconnect()) {
                channel = ssh_manager_->get_channel(target_address_, target_port_);
                if (channel == nullptr) {
                    Logger::error("Session: Переподключение не удалось. Отправляем ошибку подключения клиенту.");
                    send_reply(0x05); // Подключение отказано
                    return;
                }
            }
            else {
                Logger::error("Session: Переподключение не удалось. Отправляем ошибку подключения клиенту.");
                send_reply(0x05); // Подключение отказано
                return;
            }
        }

        // Сохранение SSH-канала для передачи данных
        ssh_channel_ = channel;

        // Отправка успешного ответа клиенту
        send_reply(0x00);

        // Начало передачи данных между клиентом и SSH-каналом
        start_relay();
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
                        }
                        else {
                            // Если произошла ошибка, закрытие соединения
                            do_close();
                        }
                    }
                    else {
                        Logger::error("Session: Ошибка отправки ответа: ", ec.message());
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
                            Logger::error("Session: Ошибка записи в SSH-канал: ", ssh_manager_->get_error_message());
                            do_close();
                            return;
                        }

                        // Продолжение чтения от клиента
                        relay_client_to_ssh();
                    }
                    else {
                        if (ec != boost::asio::error::eof) {
                            Logger::error("Session: Ошибка чтения от клиента: ", ec.message());
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
            Logger::error("Session: SSH-канал закрыт или недействителен.");
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
                            Logger::error("Session: Ошибка отправки данных от сервера к клиенту: ", ec.message());
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
                Logger::log("Session: SSH-канал достиг конца файла (EOF).");
                do_close();
            }
            else {
                Logger::error("Session: Ошибка чтения из SSH-канала: ", ssh_manager_->get_error_message());
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
                    Logger::log("Session: Соединение с клиентом закрыто.");
                }
                if (ssh_channel_) {
                    ssh_channel_send_eof(ssh_channel_);
                    ssh_channel_close(ssh_channel_);
                    ssh_channel_free(ssh_channel_);
                    ssh_channel_ = nullptr;
                    Logger::log("Session: SSH-канал закрыт.");
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
    Socks5Proxy(boost::asio::io_context& io_context, unsigned short port, std::size_t thread_pool_size,
               const std::string& ssh_host, int ssh_port,
               const std::string& ssh_user, const std::string& ssh_password,
               int verbosity, long timeout,
               const std::string& ciphers_c_s,
               const std::string& key_exchange,
               const std::string& hmac_c_s,
               const std::string& hostkeys,
               const std::string& compression)
        : io_context_(io_context),
          acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
          thread_pool_size_(thread_pool_size)
    {
        // Инициализация SSHManager
        ssh_manager_ = std::make_shared<SSHManager>(ssh_host, ssh_port, ssh_user, ssh_password,
                                                   verbosity, timeout,
                                                   ciphers_c_s,
                                                   key_exchange,
                                                   hmac_c_s,
                                                   hostkeys,
                                                   compression);
    }

    void start() {
        do_accept();
    }

    void run() {
        // Создание пула потоков для обработки событий
        std::vector<std::thread> threads;
        for (std::size_t i = 0; i < thread_pool_size_; ++i) {
            threads.emplace_back([this]() {
                io_context_.run();
            });
        }

        // Ожидание завершения всех потоков
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](const boost::system::error_code& ec, tcp::socket socket) {
                if (!ec) {
                    try {
                        Logger::log("Socks5Proxy: Принято подключение от ", socket.remote_endpoint());
                    }
                    catch (std::exception& e) {
                        Logger::error("Socks5Proxy: Ошибка получения удаленного конечного адреса: ", e.what());
                    }
                    // Создание новой сессии с использованием SSHManager
                    std::make_shared<Session>(std::move(socket), io_context_, ssh_manager_)->start();
                }
                else {
                    Logger::error("Socks5Proxy: Ошибка принятия подключения: ", ec.message());
                }
                do_accept();
            }
        );
    }

    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    std::size_t thread_pool_size_;

    std::shared_ptr<SSHManager> ssh_manager_;
};

// Главная функция
int main() {
    try {
        // Конфигурация для SOCKS5 Proxy и SSH-опций
        unsigned short port = 1080; // Порт SOCKS5 Proxy
        std::size_t thread_pool_size = 1; // Количество потоков (Установлено в 1 для стабильности)

        // Детали подключения SSH
        std::string ssh_host = "80.114.169.130";
        int ssh_port = 222;
        std::string ssh_user = "admin";
        std::string ssh_password = "Tmt$01!";

        // SSH-опции
        int verbosity = SSH_LOG_PROTOCOL; // Уровень логирования
        long timeout = 5; // Таймаут подключения в секундах
        std::string ciphers_c_s = "chacha20-poly1305,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc"; // Шифры
        std::string key_exchange = "curve25519-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1"; // Методы обмена ключами
        std::string hmac_c_s = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1"; // Алгоритмы HMAC
        std::string hostkeys = "ssh-rsa,ssh-dss,ecdh-sha2-nistp256"; // Предпочитаемые типы ключей хоста
        std::string compression = "none"; // Отключение сжатия

        boost::asio::io_context io_context;

        Socks5Proxy proxy(io_context, port, thread_pool_size,
                          ssh_host, ssh_port,
                          ssh_user, ssh_password,
                          verbosity, timeout,
                          ciphers_c_s,
                          key_exchange,
                          hmac_c_s,
                          hostkeys,
                          compression);
        proxy.start();

        Logger::log("Socks5Proxy: Запущен на порту ", port, " с пулом потоков размером ", thread_pool_size, ".");
        Logger::log("Socks5Proxy: Используется SSH-сервер ", ssh_host, ":", ssh_port, " с пользователем ", ssh_user, ".");

        proxy.run();
    }
    catch (std::exception& e) {
        Logger::error("Main: Исключение: ", e.what());
    }

    return 0;
}
