package socks5_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/socks5"
)

// proxyStub — минимальный SOCKS5-сервер, доводящий соединение до цели.
type proxyStub struct {
	listener net.Listener
	target   string // куда соединять после CONNECT
	needAuth bool
	user     string
	password string
	// reply подменяет код ответа на CONNECT.
	reply byte
	// seenHost и seenPort — что попросил клиент. Пишутся из горутины
	// сервера, читаются из теста, поэтому под мьютексом.
	mu       sync.Mutex
	seenHost string
	seenPort int
	done     chan struct{}
}

func newProxy(t *testing.T, target string) *proxyStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("прокси: %v", err)
	}
	p := &proxyStub{listener: ln, target: target, done: make(chan struct{})}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close(); <-p.done })
	return p
}

func (p *proxyStub) addr() string { return p.listener.Addr().String() }

func (p *proxyStub) serve() {
	defer close(p.done)
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *proxyStub) handle(conn net.Conn) {
	defer conn.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if p.needAuth {
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		ver := make([]byte, 2)
		if _, err := io.ReadFull(conn, ver); err != nil {
			return
		}
		user := make([]byte, ver[1])
		_, _ = io.ReadFull(conn, user)
		plen := make([]byte, 1)
		_, _ = io.ReadFull(conn, plen)
		pass := make([]byte, plen[0])
		_, _ = io.ReadFull(conn, pass)
		if string(user) != p.user || string(pass) != p.password {
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 5)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	host := make([]byte, req[4])
	if _, err := io.ReadFull(conn, host); err != nil {
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	p.mu.Lock()
	p.seenHost, p.seenPort = string(host), int(port[0])<<8|int(port[1])
	p.mu.Unlock()

	code := p.reply
	if code != 0 {
		_, _ = conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	upstream, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer upstream.Close()
	go func() { _, _ = io.Copy(upstream, conn) }()
	_, _ = io.Copy(conn, upstream)
}

// echoServer отвечает на любой HTTP-запрос одинаково.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("сервер: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "привет")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestDialerConnectsThroughProxy(t *testing.T) {
	backend := echoServer(t)
	p := newProxy(t, backend)
	d := &socks5.Dialer{Address: p.addr()}

	client := &http.Client{Transport: socks5.Transport(d), Timeout: 5 * time.Second}
	resp, err := client.Get("http://пример.рф/") // имя разрешает прокси, не мы
	if err != nil {
		t.Fatalf("запрос через прокси: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if string(body) != "привет" {
		t.Fatalf("тело %q", body)
	}
	p.mu.Lock()
	host, port := p.seenHost, p.seenPort
	p.mu.Unlock()
	if port != 80 {
		t.Errorf("прокси попросили порт %d, ожидался 80", port)
	}
	if host == "" {
		t.Error("имя хоста до прокси не дошло")
	}
}

func TestDialerAuthenticates(t *testing.T) {
	backend := echoServer(t)
	p := newProxy(t, backend)
	p.needAuth, p.user, p.password = true, "боб", "секрет"
	d := &socks5.Dialer{Address: p.addr(), User: "боб", Password: "секрет"}

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("подключение с паролем: %v", err)
	}
	_ = conn.Close()
}

func TestDialerReportsRejectedCredentials(t *testing.T) {
	p := newProxy(t, "127.0.0.1:1")
	p.needAuth, p.user, p.password = true, "боб", "секрет"
	d := &socks5.Dialer{Address: p.addr(), User: "боб", Password: "неверный"}

	_, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("неверный пароль принят")
	}
	if !strings.Contains(err.Error(), "логин или пароль") {
		t.Errorf("непонятная ошибка: %v", err)
	}
}

// Код отказа прокси должен превращаться в читаемое сообщение, иначе оператор
// видит только «не работает».
func TestDialerExplainsProxyRefusal(t *testing.T) {
	p := newProxy(t, "127.0.0.1:1")
	p.reply = 0x05 // в соединении отказано
	d := &socks5.Dialer{Address: p.addr()}

	_, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("отказ прокси принят за успех")
	}
	if !strings.Contains(err.Error(), "отказано") {
		t.Errorf("код отказа не расшифрован: %v", err)
	}
}

func TestDialerRejectsNonTCP(t *testing.T) {
	d := &socks5.Dialer{Address: "127.0.0.1:1080"}
	if _, err := d.DialContext(context.Background(), "udp", "example.com:80"); err == nil {
		t.Fatal("udp принят")
	}
}

// Без адреса прокси транспорта быть не должно: вызывающий код обязан
// воспользоваться прямым выходом, а не молча получить неработающий клиент.
func TestTransportNilWithoutAddress(t *testing.T) {
	if socks5.Transport(nil) != nil {
		t.Error("для nil-диалера собран транспорт")
	}
	if socks5.Transport(&socks5.Dialer{}) != nil {
		t.Error("для пустого адреса собран транспорт")
	}
}

// Прокси волен вернуть привязанный адрес в любом из трёх видов; хвост нужно
// вычитать целиком, иначе его байты уедут в тело HTTP-ответа.
func TestDialerHandlesAllBoundAddressTypes(t *testing.T) {
	cases := map[string][]byte{
		"IPv4":  {0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x1f, 0x90},
		"домен": append([]byte{0x05, 0x00, 0x00, 0x03, 3, 'a', 'b', 'c'}, 0x1f, 0x90),
		"IPv6":  append(append([]byte{0x05, 0x00, 0x00, 0x04}, make([]byte, 16)...), 0x1f, 0x90),
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("слушатель: %v", err)
			}
			defer ln.Close()
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				head := make([]byte, 2)
				_, _ = io.ReadFull(conn, head)
				_, _ = io.ReadFull(conn, make([]byte, head[1]))
				_, _ = conn.Write([]byte{0x05, 0x00})
				req := make([]byte, 5)
				_, _ = io.ReadFull(conn, req)
				_, _ = io.ReadFull(conn, make([]byte, int(req[4])+2))
				_, _ = conn.Write(reply)
				_, _ = conn.Write([]byte("хвост"))
			}()

			d := &socks5.Dialer{Address: ln.Addr().String()}
			conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
			if err != nil {
				t.Fatalf("подключение: %v", err)
			}
			defer conn.Close()
			rest, _ := io.ReadAll(conn)
			if string(rest) != "хвост" {
				t.Fatalf("после рукопожатия прочитано %q: адрес вычитан не полностью", rest)
			}
		})
	}
}

// Слишком длинное имя в SOCKS5 не помещается в один байт длины.
func TestDialerRejectsOverlongHost(t *testing.T) {
	d := &socks5.Dialer{Address: "127.0.0.1:1080"}
	long := strings.Repeat("a", 300) + ":80"
	if _, err := d.DialContext(context.Background(), "tcp", long); err == nil {
		t.Fatal("слишком длинное имя принято")
	}
}

func TestDialerRejectsBadAddress(t *testing.T) {
	d := &socks5.Dialer{Address: "127.0.0.1:1080"}
	for _, addr := range []string{"без-порта", "example.com:0", "example.com:99999"} {
		if _, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Errorf("адрес %q принят", addr)
		}
	}
}
