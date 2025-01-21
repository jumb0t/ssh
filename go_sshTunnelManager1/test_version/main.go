package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	socks5proxy "github.com/cloudfoundry/socks5-proxy"
	"golang.org/x/crypto/ssh"
)

// TunnelConfig представляет конфигурацию для каждого SSH туннеля
type TunnelConfig struct {
	Name          string   `json:"name"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	LocalPort     int      `json:"local_port"`
	Group         string   `json:"group,omitempty"`
	Comment       string   `json:"comment,omitempty"`
	SSHOptions    []string `json:"ssh_options,omitempty"`
	SerialNumber  int      `json:"serial_number,omitempty"`
	MaxReconnects int      `json:"max_reconnects"`
	AutoReconnect int      `json:"auto_reconnects"`
}

// SSHSettings представляет настройки SSH соединений из app.json
type SSHSettings struct {
	MACAlgorithms     []string `json:"mac_algorithms"`
	KEXAlgorithms     []string `json:"kex_algorithms"`
	HostKeyAlgorithms []string `json:"host_key_algorithms"`
	Ciphers           []string `json:"ciphers,omitempty"`
}

// AppConfig представляет конфигурацию приложения, загруженную из app.json
type AppConfig struct {
	Debug                 bool        `json:"debug"`
	TimeoutSeconds        int         `json:"timeout_seconds"`
	ReconnectIntervalSecs int         `json:"reconnect_interval_seconds"`
	LogFile               string      `json:"log_file"`
	SSHSettings           SSHSettings `json:"ssh_settings"`
	GlobalMaxReconnects   int         `json:"global_max_reconnects,omitempty"`
	GlobalAutoReconnects  int         `json:"global_auto_reconnects,omitempty"`
}

// ConfigManager хранит как AppConfig, так и SSH туннели (в виде слайса TunnelConfig)
type ConfigManager struct {
	AppConfig  AppConfig
	SSHTunnels []TunnelConfig
}

// DebugLog выводит отладочные сообщения, если отладка включена
func (cm *ConfigManager) DebugLog(format string, v ...interface{}) {
	if cm.AppConfig.Debug {
		log.Printf("DEBUG: "+format, v...)
	}
}

// readAppConfig читает и парсит конфигурацию приложения из JSON файла
func readAppConfig(filePath string) (AppConfig, error) {
	var appConfig AppConfig
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return appConfig, fmt.Errorf("не удалось прочитать файл конфигурации приложения: %w", err)
	}
	err = json.Unmarshal(data, &appConfig)
	if err != nil {
		return appConfig, fmt.Errorf("не удалось распарсить файл конфигурации приложения: %w", err)
	}
	return appConfig, nil
}

// readSSHTunnels читает и парсит конфигурацию SSH туннелей из JSON файла (массив)
func readSSHTunnels(filePath string) ([]TunnelConfig, error) {
	var tunnels []TunnelConfig
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return tunnels, fmt.Errorf("не удалось прочитать файл SSH конфигурации: %w", err)
	}
	err = json.Unmarshal(data, &tunnels)
	if err != nil {
		return tunnels, fmt.Errorf("не удалось распарсить файл SSH конфигурации: %w", err)
	}
	return tunnels, nil
}

// validateAppConfig валидирует конфигурацию приложения
func validateAppConfig(appConfig AppConfig) error {
	if appConfig.TimeoutSeconds <= 0 {
		return fmt.Errorf("timeout_seconds должно быть больше 0")
	}
	if appConfig.ReconnectIntervalSecs <= 0 {
		return fmt.Errorf("reconnect_interval_seconds должно быть больше 0")
	}
	// Дополнительные проверки можно добавить здесь
	return nil
}

// validateSSHTunnels валидирует конфигурацию SSH туннелей
func validateSSHTunnels(tunnels []TunnelConfig) error {
	if len(tunnels) == 0 {
		return fmt.Errorf("нет определенных туннелей в SSH конфигурации")
	}
	for i, tunnel := range tunnels {
		if tunnel.Name == "" {
			return fmt.Errorf("туннель на индексе %d имеет пустое имя", i)
		}
		if tunnel.Host == "" {
			return fmt.Errorf("туннель '%s' имеет пустой host", tunnel.Name)
		}
		if tunnel.Port <= 0 || tunnel.Port > 65535 {
			return fmt.Errorf("туннель '%s' имеет неверный port: %d", tunnel.Name, tunnel.Port)
		}
		if tunnel.Username == "" {
			return fmt.Errorf("туннель '%s' имеет пустой username", tunnel.Name)
		}
		if tunnel.Password == "" {
			return fmt.Errorf("туннель '%s' имеет пустой password", tunnel.Name)
		}
		if tunnel.LocalPort <= 0 || tunnel.LocalPort > 65535 {
			return fmt.Errorf("туннель '%s' имеет неверный local_port: %d", tunnel.Name, tunnel.LocalPort)
		}
		if tunnel.MaxReconnects < 0 {
			return fmt.Errorf("туннель '%s' имеет отрицательный max_reconnects", tunnel.Name)
		}
		if tunnel.AutoReconnect < 0 {
			return fmt.Errorf("туннель '%s' имеет отрицательный auto_reconnects", tunnel.Name)
		}
	}
	return nil
}

// createAuthMethods создает методы аутентификации SSH на основе пароля туннеля и поддержки KeyboardInteractive
func createAuthMethods(password string) []ssh.AuthMethod {
	authMethods := []ssh.AuthMethod{}
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	// Добавляем метод KeyboardInteractive
	authMethods = append(authMethods, ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
		answers = make([]string, len(questions))
		for i, q := range questions {
			if echos[i] {
				fmt.Printf("%s: ", q)
				fmt.Scanln(&answers[i])
			} else {
				// Если эхо отключено, можно использовать библиотеку для скрытого ввода
				fmt.Printf("%s: ", q)
				fmt.Scanln(&answers[i])
			}
		}
		return answers, nil
	}))
	return authMethods
}

// setupLogger настраивает логирование на основе конфигурации приложения
func setupLogger(appConfig AppConfig) error {
	if appConfig.LogFile != "" {
		file, err := os.OpenFile(appConfig.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("не удалось открыть файл логов '%s': %w", appConfig.LogFile, err)
		}
		multiWriter := io.MultiWriter(os.Stdout, file)
		log.SetOutput(multiWriter)
	} else {
		log.SetOutput(os.Stdout)
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	return nil
}

// connectAndServe устанавливает SSH соединение и запускает SOCKS5 прокси для данного туннеля
func (cm *ConfigManager) connectAndServe(tunnel TunnelConfig, wg *sync.WaitGroup) {
	defer wg.Done()

	reconnectAttempts := 0

	for {
		authMethods := createAuthMethods(tunnel.Password)

		clientConfig := &ssh.ClientConfig{
			User:              tunnel.Username,
			Auth:              authMethods,
			HostKeyCallback:   ssh.InsecureIgnoreHostKey(), // Используем InsecureIgnoreHostKey как вы просили
			HostKeyAlgorithms: cm.AppConfig.SSHSettings.HostKeyAlgorithms,
			Timeout:           time.Duration(cm.AppConfig.TimeoutSeconds) * time.Second,
			Config: ssh.Config{
				MACs:         cm.AppConfig.SSHSettings.MACAlgorithms,
				KeyExchanges: cm.AppConfig.SSHSettings.KEXAlgorithms,
				Ciphers:      cm.AppConfig.SSHSettings.Ciphers,
			},
		}

		// Установка стандартных значений SSH Config, если они не заданы
		clientConfig.Config.SetDefaults()

		sshAddress := fmt.Sprintf("%s:%d", tunnel.Host, tunnel.Port)
		log.Printf("[%s] Попытка подключения к %s", tunnel.Name, sshAddress)

		sshClient, err := ssh.Dial("tcp", sshAddress, clientConfig)
		if err != nil {
			reconnectAttempts++
			log.Printf("[%s] Не удалось подключиться к %s (попытка %d): %v", tunnel.Name, sshAddress, reconnectAttempts, err)

			// Проверка на ошибки аутентификации
			if isAuthError(err) {
				log.Printf("[%s] Ошибка аутентификации: %v. Завершение попыток подключения.", tunnel.Name, err)
				return
			}

			if reconnectAttempts >= tunnel.MaxReconnects {
				log.Printf("[%s] Превышено максимальное количество попыток подключения к %s", tunnel.Name, sshAddress)
				return
			}

			log.Printf("[%s] Повторная попытка подключения к %s через %d секунд...", tunnel.Name, sshAddress, cm.AppConfig.ReconnectIntervalSecs)
			time.Sleep(time.Duration(cm.AppConfig.ReconnectIntervalSecs) * time.Second)
			continue
		}

		reconnectAttempts = 0
		log.Printf("[%s] Успешно подключено к %s", tunnel.Name, sshAddress)

		// Поддержание соединения keep-alive
		go cm.keepAlive(sshClient, tunnel)

		dialFunc := func(network, address string) (net.Conn, error) {
			conn, err := sshClient.Dial(network, address)
			if err != nil {
				cm.DebugLog("[%s] Ошибка при подключении к %s через SSH: %v", tunnel.Name, address, err)
				return nil, err
			}
			cm.DebugLog("[%s] Успешно подключено к %s через SSH", tunnel.Name, address)
			return conn, nil
		}

		logger := log.New(os.Stdout, fmt.Sprintf("socks5-proxy-%s: ", tunnel.Name), log.LstdFlags)
		hostKey := socks5proxy.NewHostKey()
		proxy := socks5proxy.NewSocks5Proxy(hostKey, logger, 30*time.Second)
		proxy.SetListenPort(tunnel.LocalPort)

		log.Printf("[%s] Запуск SOCKS5 прокси на порту %d...", tunnel.Name, tunnel.LocalPort)

		// Запуск SOCKS5 прокси как блокирующего вызова
		err = proxy.StartWithDialer(dialFunc)
		if err != nil {
			log.Printf("[%s] Ошибка при запуске SOCKS5 прокси: %v", tunnel.Name, err)
		}

		// SSH соединение закрыто, пытаемся переподключиться
		log.Printf("[%s] SSH соединение к %s закрыто. Переподключение...", tunnel.Name, sshAddress)

		// Закрываем SSH клиент, чтобы освободить ресурсы
		sshClient.Close()

		// Определение максимального количества попыток переподключения
		if tunnel.AutoReconnect > 0 {
			tunnel.MaxReconnects = tunnel.AutoReconnect
		} else if cm.AppConfig.GlobalAutoReconnects > 0 {
			tunnel.MaxReconnects = cm.AppConfig.GlobalAutoReconnects
		}

		reconnectAttempts++
		if reconnectAttempts >= tunnel.MaxReconnects {
			log.Printf("[%s] Превышено максимальное количество попыток переподключения к %s", tunnel.Name, sshAddress)
			break
		}

		log.Printf("[%s] Переподключение к %s через %d секунд...", tunnel.Name, sshAddress, cm.AppConfig.ReconnectIntervalSecs)
		time.Sleep(time.Duration(cm.AppConfig.ReconnectIntervalSecs) * time.Second)
	}
}

// keepAlive отправляет keep-alive запросы для поддержания SSH соединения
func (cm *ConfigManager) keepAlive(client *ssh.Client, tunnel TunnelConfig) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			log.Printf("[%s] Ошибка keep-alive: %v", tunnel.Name, err)
			client.Close()
			break
		}
		cm.DebugLog("[%s] Отправлен keep-alive", tunnel.Name)
	}
}

// isAuthError определяет, является ли ошибка связанной с аутентификацией
func isAuthError(err error) bool {
	// Проверяем, содержит ли сообщение об ошибке указанные строки
	return strings.Contains(err.Error(), "unable to authenticate") ||
		strings.Contains(err.Error(), "authentication failed") ||
		strings.Contains(err.Error(), "permission denied")
}

func main() {
	// Определение флагов командной строки
	sshConfigPath := flag.String("conf-ssh", "ssh.json", "Путь к SSH конфигурационному JSON файлу")
	appConfigPath := flag.String("conf-app", "app.json", "Путь к конфигурационному JSON файлу приложения")
	flag.Parse()

	// Чтение и парсинг конфигурации приложения
	appConfig, err := readAppConfig(*appConfigPath)
	if err != nil {
		log.Fatalf("Ошибка при загрузке конфигурации приложения: %v", err)
	}

	// Настройка логирования
	err = setupLogger(appConfig)
	if err != nil {
		log.Fatalf("Ошибка при настройке логирования: %v", err)
	}

	// Отладочный лог для загрузки конфигурации приложения
	if appConfig.Debug {
		log.Println("DEBUG: Конфигурация приложения успешно загружена")
	}

	// Валидация конфигурации приложения
	err = validateAppConfig(appConfig)
	if err != nil {
		log.Fatalf("Недопустимая конфигурация приложения: %v", err)
	}

	// Чтение и парсинг SSH туннелей
	sshtunnels, err := readSSHTunnels(*sshConfigPath)
	if err != nil {
		log.Fatalf("Ошибка при загрузке SSH конфигурации: %v", err)
	}

	// Валидация SSH туннелей
	err = validateSSHTunnels(sshtunnels)
	if err != nil {
		log.Fatalf("Недопустимая SSH конфигурация: %v", err)
	}

	// Инициализация ConfigManager
	configManager := ConfigManager{
		AppConfig:  appConfig,
		SSHTunnels: sshtunnels,
	}

	// Используем WaitGroup для ожидания завершения всех горутин
	var wg sync.WaitGroup

	// Ограничение количества одновременно работающих горутин (например, 100)
	maxGoroutines := 600
	guard := make(chan struct{}, maxGoroutines)

	// Запуск SSH туннелей
	for _, tunnel := range configManager.SSHTunnels {
		tunnelCopy := tunnel
		wg.Add(1)
		guard <- struct{}{} // блокировка, если достигнуто максимальное количество горутин
		go func(t TunnelConfig) {
			defer func() { <-guard }()
			configManager.connectAndServe(t, &wg)
		}(tunnelCopy)
	}

	// Обработка корректного завершения работы
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		log.Printf("Получен сигнал '%s'. Завершение работы...", sig)
		os.Exit(0)
	}()

	// Ожидание завершения всех горутин
	wg.Wait()
}
