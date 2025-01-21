package main

import (
	"context"
	"fmt"
	"log"
	"net"
//	"os"
	"time"

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
)

// Константы
const (
	SSHUser              = "user"      // Замените на ваш SSH логин
	SSHPassword          = "user"      // Замените на ваш SSH пароль
	SSHHost              = "127.0.0.1:22"     // Замените на адрес и порт вашего SSH сервера
	SOCKS5LocalPort      = 1080                     // Локальный порт для SOCKS5
	ReconnectInterval    = time.Second              // Интервал проверки соединения
	KeepAliveInterval    = time.Minute              // Интервал KeepAlive
	KeepAliveTimeout     = time.Second * 15         // Таймаут KeepAlive
)
// Конфигурация для SSH клиента с кастомными алгоритмами
func getSSHClientConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 10,
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
}

// DialSSH создает соединение с SSH-сервером.
func DialSSH() (*ssh.Client, error) {
	// Настройки клиента
	config := getSSHClientConfig()

	client, err := ssh.Dial("tcp", SSHHost, config)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к SSH серверу: %w", err)
	}
	return client, nil
}

// StartSOCKS5 запускает локальный SOCKS5-прокси, используя SSH в качестве транспорта.
func StartSOCKS5(client *ssh.Client, localPort int) error {
	// Создаем SOCKS5 сервер
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Используем SSH клиент для создания туннеля
			return client.Dial(network, addr)
		},
	}

	socksServer, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("не удалось создать SOCKS5 сервер: %w", err)
	}

	// Слушаем локальный порт
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("не удалось запустить SOCKS5 сервер: %w", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 прокси запущен на 127.0.0.1:%d", localPort)

	// Обработка входящих соединений
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Ошибка принятия соединения: %s", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			err := socksServer.ServeConn(c)
			if err != nil {
				log.Printf("Ошибка обработки SOCKS5 соединения: %s", err)
			}
		}(conn)
	}
}

// KeepAlive отправляет запросы keep-alive.
func KeepAlive(client *ssh.Client) {
	ticker := time.NewTicker(KeepAliveInterval)
	defer ticker.Stop()

	for range ticker.C {
		_, _, err := client.SendRequest("keepalive@golang.org", true, nil)
		if err != nil {
			log.Printf("Ошибка отправки KeepAlive: %s", err)
			client.Close()
			return
		}
	}
}

// ReconnectSSH проверяет соединение и пытается переподключиться при необходимости.
func ReconnectSSH() {
	for {
		client, err := DialSSH()
		if err != nil {
			log.Printf("Ошибка подключения: %s. Повторная попытка через %s", err, ReconnectInterval)
			time.Sleep(ReconnectInterval)
			continue
		}

		// Установить KeepAlive
		go KeepAlive(client)

		// Запустить SOCKS5
		err = StartSOCKS5(client, SOCKS5LocalPort)
		if err != nil {
			log.Printf("Ошибка запуска SOCKS5: %s", err)
			client.Close()
		}

		// Если соединение разорвано, попытаться подключиться снова
		client.Close()
		log.Println("Соединение разорвано. Переподключение...")
		time.Sleep(ReconnectInterval)
	}
}

func main() {
	log.Println("Запуск SSH клиента с SOCKS5...")
	ReconnectSSH()
}
