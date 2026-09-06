// Package socks5 — минимальный клиент SOCKS5 для исходящих подключений.
//
// Написан вручную, а не взят библиотекой, по той же причине, по какой во всём
// проекте почти нет зависимостей: нужен ровно один сценарий — CONNECT к
// доменному имени, с паролем или без. Это полсотни строк по RFC 1928 и
// RFC 1929, и держать ради них чужой код с собственным графом зависимостей
// невыгодно.
package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Dialer подключается к адресату через SOCKS5-прокси.
type Dialer struct {
	// Address — адрес прокси, например "127.0.0.1:31675".
	Address string
	// User и Password необязательны: без них согласуется метод «без аутентификации».
	User     string
	Password string
	// Net используется для подключения к самому прокси. Нужен тестам.
	Net func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Коды ответа SOCKS5, которые стоит различать в сообщении об ошибке.
var replyText = map[byte]string{
	1: "общий сбой SOCKS-сервера",
	2: "соединение запрещено правилами",
	3: "сеть недоступна",
	4: "хост недоступен",
	5: "в соединении отказано",
	6: "истёк TTL",
	7: "команда не поддерживается",
	8: "тип адреса не поддерживается",
}

// DialContext устанавливает TCP-соединение с addr через прокси.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks5: сеть %q не поддерживается", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: адрес %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks5: некорректный порт в %q", addr)
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("socks5: имя хоста длиннее 255 байт")
	}

	dial := d.Net
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}
	conn, err := dial(ctx, "tcp", d.Address)
	if err != nil {
		return nil, fmt.Errorf("socks5: подключение к прокси %s: %w", d.Address, err)
	}

	// Отменённый контекст обязан обрывать и рукопожатие: иначе запрос,
	// который уже никому не нужен, продолжал бы висеть на неотвечающем прокси.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })

	if err := d.handshake(conn, host, port); err != nil {
		stop()
		_ = conn.Close()
		return nil, err
	}
	stop()
	// Дедлайн снимаем: дальше соединением распоряжается вызывающий код, и
	// оставленный срок оборвал бы, например, скачивание аватарки.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *Dialer) handshake(conn net.Conn, host string, port int) error {
	if err := d.negotiate(conn); err != nil {
		return err
	}
	// Запрос CONNECT с адресом в виде доменного имени: разрешать имя должен
	// прокси, иначе смысл прокси частично теряется.
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: запрос CONNECT: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5: ответ на CONNECT: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks5: неожиданная версия ответа %d", head[0])
	}
	if head[1] != 0x00 {
		if text, ok := replyText[head[1]]; ok {
			return fmt.Errorf("socks5: %s", text)
		}
		return fmt.Errorf("socks5: прокси отказал, код %d", head[1])
	}
	// Хвост ответа — привязанный адрес; он нам не нужен, но вычитать его
	// обязательно, иначе байты уедут в тело HTTP-ответа.
	return skipBoundAddress(conn, head[3])
}

// negotiate согласует метод аутентификации.
func (d *Dialer) negotiate(conn net.Conn) error {
	methods := []byte{0x00} // без аутентификации
	if d.User != "" {
		methods = []byte{0x02, 0x00} // сначала логин с паролем
	}
	hello := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(hello); err != nil {
		return fmt.Errorf("socks5: приветствие: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: ответ на приветствие: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5: неожиданная версия %d", resp[0])
	}
	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		return d.authenticate(conn)
	case 0xFF:
		return errors.New("socks5: прокси не принял ни один метод аутентификации")
	default:
		return fmt.Errorf("socks5: прокси выбрал неизвестный метод %d", resp[1])
	}
}

// authenticate выполняет вход логином и паролем по RFC 1929.
func (d *Dialer) authenticate(conn net.Conn) error {
	if len(d.User) > 255 || len(d.Password) > 255 {
		return errors.New("socks5: логин или пароль длиннее 255 байт")
	}
	msg := []byte{0x01, byte(len(d.User))}
	msg = append(msg, d.User...)
	msg = append(msg, byte(len(d.Password)))
	msg = append(msg, d.Password...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("socks5: отправка учётных данных: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: ответ на учётные данные: %w", err)
	}
	// Версия подпереговоров по RFC 1929 своя и равна 1, а не 5. Проверяем её
	// по той же причине, что и версию в negotiate: разошедшись с прокси в
	// разборе, дальше мы читали бы его байты как ответ на CONNECT.
	if resp[0] != 0x01 {
		return fmt.Errorf("socks5: неожиданная версия аутентификации %d", resp[0])
	}
	if resp[1] != 0x00 {
		return errors.New("socks5: прокси отклонил логин или пароль")
	}
	return nil
}

// skipBoundAddress вычитывает адрес из ответа прокси.
func skipBoundAddress(conn net.Conn, addrType byte) error {
	var n int
	switch addrType {
	case 0x01:
		n = 4 + 2
	case 0x04:
		n = 16 + 2
	case 0x03:
		size := make([]byte, 1)
		if _, err := io.ReadFull(conn, size); err != nil {
			return fmt.Errorf("socks5: длина адреса в ответе: %w", err)
		}
		n = int(size[0]) + 2
	default:
		return fmt.Errorf("socks5: неизвестный тип адреса %d в ответе", addrType)
	}
	if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
		return fmt.Errorf("socks5: адрес в ответе: %w", err)
	}
	return nil
}

// Transport собирает http.Transport, ходящий через прокси. Если Dialer
// пустой, возвращается nil — вызывающий код воспользуется прямым выходом.
func Transport(d *Dialer) *http.Transport {
	if d == nil || d.Address == "" {
		return nil
	}
	return &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}
