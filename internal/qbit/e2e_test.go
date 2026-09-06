package qbit_test

// Сквозная проверка всей цепочки: резидент добавляет торрент через прокси,
// загрузка доходит до конца, бот сообщает в чат и пишет автору в личку,
// воркер выключается.
//
// Отдельно от юнит-тестов рядом: те проверяют части (прокси отдаёт торренты
// воркеру, воркер замечает завершение, уведомитель шлёт нужную форму), а
// собрать из исправных частей неработающее целое — ровно та ошибка, которую
// они пропустят. Здесь всё собрано так же, как в main.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/qbit"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
)

type e2eMessages struct{}

func (e2eMessages) TorrentAdded() string      { return "{user} добавил {torrent}" }
func (e2eMessages) TorrentDownloaded() string { return "Торрент {torrent} загрузился" }

func TestAddedTorrentReachesChatAndAuthorInbox(t *testing.T) {
	var mu sync.Mutex
	progress := 0.3
	qb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/auth/login":
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "s1", Path: "/"})
			_, _ = w.Write([]byte("Ok."))
		case "/api/v2/torrents/info":
			mu.Lock()
			p := progress
			mu.Unlock()
			_ = json.NewEncoder(w).Encode([]qbit.TorrentInfo{
				{Hash: "C12FE1C06BBA254A9DC9F519B335AA7C1367A88A", Name: "Ubuntu 24.04", Progress: p},
			})
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer qb.Close()

	var tgMu sync.Mutex
	var sent []url.Values
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tgMu.Lock()
		sent = append(sent, r.PostForm)
		tgMu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer tg.Close()

	log := quiet()
	target, _ := url.Parse(qb.URL)
	base, _ := url.Parse("https://inside.akiba.space")

	notifier := tgnotify.New(tgnotify.Config{
		Token: "1:t", ChatID: "-100", BaseURL: base.String(), APIBase: tg.URL,
	}, e2eMessages{}, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := qbit.NewClient(target, &http.Client{}, "u", "p", true)
	watcher := qbit.NewDownloadWatcher(ctx, client, notifier, log, 50*time.Millisecond)
	proxy := qbit.NewProxy("/qbittorrent", target, client, watcher, notifier,
		auth.HostPolicy{Base: base}, log)

	// Резидент добавляет торрент magnet-ссылкой.
	body := "urls=" + url.QueryEscape("magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=Ubuntu")
	r := httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{
		TelegramID: "42424242", Username: "alice", FirstName: "Алиса", IsResident: true,
	}))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("добавление вернуло %d", w.Code)
	}
	if !watcher.Running() {
		t.Fatal("воркер не поднялся на добавление торрента")
	}

	// Загрузка дошла до конца.
	mu.Lock()
	progress = 1
	mu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tgMu.Lock()
		n := len(sent)
		tgMu.Unlock()
		if n >= 2 && !watcher.Running() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	tgMu.Lock()
	defer tgMu.Unlock()
	if len(sent) < 2 {
		t.Fatalf("отправлено %d сообщений, ожидалось 2 (чат + личка)", len(sent))
	}
	chat, dm := sent[0], sent[1]
	if chat.Get("chat_id") != "-100" || chat.Get("disable_notification") != "true" {
		t.Errorf("сообщение в чат неверное: %v", chat)
	}
	if dm.Get("chat_id") != "42424242" {
		t.Errorf("личное сообщение ушло не автору: %q", dm.Get("chat_id"))
	}
	if dm.Get("disable_notification") != "false" {
		t.Errorf("личное сообщение без звука: %q", dm.Get("disable_notification"))
	}
	if !strings.Contains(dm.Get("text"), "Ubuntu 24.04") {
		t.Errorf("в личном сообщении нет имени торрента: %q", dm.Get("text"))
	}
	if watcher.Running() {
		t.Error("воркер не остановился после опустошения хранилища")
	}
}
