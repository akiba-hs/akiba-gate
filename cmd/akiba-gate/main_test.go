package main

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/config"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
	"github.com/akiba-hs/akiba-gate/internal/userpic"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Без SOCKS5 клиент обязан остаться на транспорте по умолчанию: прямой
// выход в Telegram — это отсутствие транспорта, а не пустой транспорт.
func TestTelegramClientGoesDirectWithoutProxy(t *testing.T) {
	c := newTelegramClient(&config.Config{Timeout: 5 * time.Second}, quietLog())

	if c.Transport != nil {
		t.Fatalf("без SOCKS5 подставлен транспорт %T", c.Transport)
	}
	if c.Timeout != 5*time.Second {
		t.Errorf("тайм-аут = %v", c.Timeout)
	}
}

// С заданным SOCKS5 транспорт обязан появиться.
func TestTelegramClientUsesProxyWhenConfigured(t *testing.T) {
	c := newTelegramClient(&config.Config{
		Timeout: 5 * time.Second, SocksAddress: "127.0.0.1:1080",
	}, quietLog())

	if c.Transport == nil {
		t.Fatal("SOCKS5 задан, а транспорт не подставлен")
	}
}

// Прокси в конфигурации один на весь Telegram, значит и клиент обязан быть
// один: и у аватарок (t.me), и у бота (api.telegram.org). Разные клиенты —
// это ровно тот случай, когда бот молчит, а аватарки грузятся, или наоборот.
func TestTelegramClientIsSharedByUserPicAndBot(t *testing.T) {
	log := quietLog()
	cfg := &config.Config{Timeout: 5 * time.Second, SocksAddress: "127.0.0.1:1080"}
	tgClient := newTelegramClient(cfg, log)

	pic := userpic.Handler{HTTP: tgClient, Log: log}
	bot := tgnotify.New(tgnotify.Config{
		Token: "t", ChatID: "1", BaseURL: "https://inside.akiba.space", HTTP: tgClient,
	}, staticMessages{}, log)

	if pic.HTTP != bot.HTTPClient() {
		t.Fatal("аватарки и бот ходят в Telegram разными клиентами")
	}
	if pic.HTTP.Transport == nil {
		t.Fatal("общий клиент остался без SOCKS5-транспорта")
	}
}

type staticMessages struct{}

func (staticMessages) TorrentAdded() string      { return "{user}: {torrent}" }
func (staticMessages) TorrentDownloaded() string { return "{torrent} загрузился" }
