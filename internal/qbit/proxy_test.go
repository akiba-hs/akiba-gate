package qbit_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/qbit"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
	"github.com/akiba-hs/akiba-gate/internal/torrent"
)

// capturedRequest — то, что реально дошло до qBittorrent.
type capturedRequest struct {
	Path   string
	Host   string
	Cookie string
	SID    string
	Origin string
	Body   []byte
	Akiba  string
	Fwd    string
}

// memoryAnnouncer запоминает сообщения, которые ушли бы в чат.
type memoryAnnouncer struct {
	mu     sync.Mutex
	events []tgnotify.Event
}

func (m *memoryAnnouncer) Notify(_ context.Context, e tgnotify.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

// wait дожидается n сообщений: отправка идёт в отдельной горутине, чтобы не
// задерживать ответ резиденту.
func (m *memoryAnnouncer) wait(t *testing.T, n int) []tgnotify.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := m.all(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("не дождались %d сообщений в чат, пришло %d", n, len(m.all()))
	return nil
}

func (m *memoryAnnouncer) all() []tgnotify.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]tgnotify.Event(nil), m.events...)
}

// memoryTracker подменяет воркер загрузок: запоминает, что взято под
// наблюдение, и ничего никуда не опрашивает.
type memoryTracker struct {
	mu    sync.Mutex
	items []qbit.Watched
}

func (m *memoryTracker) Track(items ...qbit.Watched) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, items...)
}

func (m *memoryTracker) all() []qbit.Watched {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]qbit.Watched(nil), m.items...)
}

// newProxyEnv поднимает фальшивый qBittorrent и прокси перед ним.
func newProxyEnv(t *testing.T) (*qbit.Proxy, *memoryTracker, *capturedRequest, *memoryAnnouncer) {
	t.Helper()
	captured := &capturedRequest{}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Fwd = r.Header.Get("X-Forwarded-Host")
		if r.URL.Path == "/api/v2/auth/login" {
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "sid-123", Path: "/"})
			_, _ = w.Write([]byte("Ok."))
			return
		}
		body, _ := io.ReadAll(r.Body)
		captured.Path = r.URL.Path
		captured.Host = r.Host
		captured.Cookie = r.Header.Get("Cookie")
		captured.Origin = r.Header.Get("Origin")
		captured.Body = body
		captured.Akiba = r.Header.Get(auth.HeaderUID)
		if c, err := r.Cookie("SID"); err == nil {
			captured.SID = c.Value
		}
		// qBittorrent на каждый ответ ставит свою cookie сессии.
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: "sid-123", Path: "/"})
		_, _ = w.Write([]byte("Ok."))
	}))
	t.Cleanup(backend.Close)

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	client := qbit.NewClient(target, noRedirectClient(), "admin", "secret", true)
	tracker := &memoryTracker{}
	ann := &memoryAnnouncer{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	base, _ := url.Parse("https://inside.akiba.space")
	hosts := auth.HostPolicy{Base: base}
	return qbit.NewProxy("/qbittorrent", target, client, tracker, ann, hosts, log), tracker, captured, ann
}

// authorized оборачивает запрос как это делает Guard.
func authorized(r *http.Request) *http.Request {
	claims := &auth.Claims{
		TelegramID: "42424242", Username: "alice",
		FirstName: "Alice", LastName: "Example", IsResident: true,
	}
	return r.WithContext(auth.WithClaims(r.Context(), claims))
}

func TestProxyStripsPrefixAndInjectsSession(t *testing.T) {
	p, _, captured, _ := newProxyEnv(t)

	r := authorized(httptest.NewRequest(http.MethodGet, "/qbittorrent/api/v2/app/version", nil))
	// Кука портала с JWT: в qBittorrent она попасть не должна.
	r.AddCookie(&http.Cookie{Name: "token", Value: "secret-jwt-value"})
	r.Header.Set(auth.HeaderUID, "tg1")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	if captured.Path != "/api/v2/app/version" {
		t.Fatalf("путь = %q, префикс не снят", captured.Path)
	}
	if captured.SID != "sid-123" {
		t.Fatalf("SID = %q, служебная сессия не подставлена", captured.SID)
	}
	if strings.Contains(captured.Cookie, "secret-jwt-value") {
		t.Fatalf("JWT утёк в qBittorrent: %q", captured.Cookie)
	}
	if captured.Akiba != "" {
		t.Fatalf("заголовок идентичности проброшен в qBittorrent: %q", captured.Akiba)
	}
	if captured.Origin == "" || strings.Contains(captured.Origin, "residents") {
		t.Fatalf("Origin = %q, ожидался адрес самого qBittorrent (защита от CSRF)", captured.Origin)
	}
}

// Cookie служебной сессии не должна доехать до браузера: иначе резидент
// получит прямой доступ к qBittorrent в обход проверки авторизации.
func TestProxyDropsBackendSetCookie(t *testing.T) {
	p, _, _, _ := newProxyEnv(t)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, authorized(httptest.NewRequest(http.MethodGet, "/qbittorrent/api/v2/app/version", nil)))

	if got := w.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("Set-Cookie отдан браузеру: %v", got)
	}
}

func TestProxyRedirectsToTrailingSlash(t *testing.T) {
	p, _, _, _ := newProxyEnv(t)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, authorized(httptest.NewRequest(http.MethodGet, "/qbittorrent", nil)))

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("код %d, ожидался 301", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/qbittorrent/" {
		t.Fatalf("Location = %q", got)
	}
}

func TestProxyRecordsTorrentAttributionAndKeepsBody(t *testing.T) {
	p, tracker, captured, _ := newProxyEnv(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("urls", "magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=ubuntu")
	part, _ := mw.CreateFormFile("torrents", "film.torrent")
	_, _ = part.Write(testsupport.TorrentFile("Тайна третьей планеты", 16384, "aaaaaaaaaaaaaaaaaaaa"))
	_ = mw.Close()
	original := buf.Bytes()

	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		bytes.NewReader(original)))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	p.ServeHTTP(httptest.NewRecorder(), r)

	// Тело обязано дойти до qBittorrent без изменений.
	if !bytes.Equal(captured.Body, original) {
		t.Fatalf("тело изменилось: дошло %d байт из %d", len(captured.Body), len(original))
	}

	events := tracker.all()
	if len(events) != 2 {
		t.Fatalf("под наблюдение взято %d торрентов, ожидалось 2: %+v", len(events), events)
	}
	for _, e := range events {
		if e.TelegramID != "42424242" || e.Username != "alice" {
			t.Fatalf("торрент взят под наблюдение без автора: %+v", e)
		}
	}
	var names []string
	for _, e := range events {
		names = append(names, e.Name)
	}
	joined := strings.Join(names, "|")
	if !strings.Contains(joined, "ubuntu") || !strings.Contains(joined, "Тайна третьей планеты") {
		t.Fatalf("имена разобраны неверно: %q", joined)
	}
}

// Ошибка разбора не должна ломать работу резидента.
func TestProxyPassesThroughUnparsableAddRequest(t *testing.T) {
	p, tracker, captured, _ := newProxyEnv(t)

	body := []byte(`{"urls":"magnet:?xt=urn:btih:aa"}`)
	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		bytes.NewReader(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("код %d, запрос должен пройти несмотря на ошибку разбора", w.Code)
	}
	if !bytes.Equal(captured.Body, body) {
		t.Fatalf("тело потеряно: %q", captured.Body)
	}
	if len(tracker.all()) != 0 {
		t.Fatalf("неразобранный запрос попал под наблюдение: %+v", tracker.all())
	}
}

// Прочие запросы к API атрибуцию не запускают.
func TestProxyDoesNotRecordNonAddRequests(t *testing.T) {
	p, tracker, _, _ := newProxyEnv(t)

	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/pause",
		strings.NewReader("hashes=all")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.ServeHTTP(httptest.NewRecorder(), r)

	if len(tracker.all()) != 0 {
		t.Fatalf("под наблюдение взято лишнее: %+v", tracker.all())
	}
}

func TestProxyReturns502WhenBackendDown(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:1")
	client := qbit.NewClient(target, noRedirectClient(), "", "", false)
	base, _ := url.Parse("https://inside.akiba.space")
	p := qbit.NewProxy("/qbittorrent", target, client, &memoryTracker{}, &memoryAnnouncer{},
		auth.HostPolicy{Base: base}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()

	p.ServeHTTP(w, authorized(httptest.NewRequest(http.MethodGet, "/qbittorrent/", nil)))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("код %d, ожидался 502", w.Code)
	}
}

// Тело крупнее лимита разбора нельзя усекать: qBittorrent получил бы
// оборванный multipart, и добавление торрента просто не сработало бы.
func TestProxyPassesOversizedBodyThroughIntact(t *testing.T) {
	p, tracker, captured, _ := newProxyEnv(t)

	// Формально корректный multipart, но с полем больше лимита разбора.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, _ := mw.CreateFormFile("torrents", "big.torrent")
	_, _ = part.Write(bytes.Repeat([]byte("A"), torrent.MaxAddBodySize+1024))
	_ = mw.Close()
	original := buf.Bytes()

	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		bytes.NewReader(original)))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()

	p.ServeHTTP(w, r)

	if len(captured.Body) != len(original) {
		t.Fatalf("тело усечено: дошло %d байт из %d", len(captured.Body), len(original))
	}
	if !bytes.Equal(captured.Body, original) {
		t.Fatal("тело изменилось при проксировании")
	}
	if len(tracker.all()) != 0 {
		t.Fatalf("слишком большое тело не должно разбираться: %+v", tracker.all())
	}
}

// Прокси подменяет Referer и Origin на адрес qBittorrent, чтобы пройти его
// защиту от CSRF, — и тем самым снимает её. Значит происхождение запроса
// обязан проверять сам шлюз, иначе любой открытый резидентом сайт сможет
// управлять загрузками и через setPreferences запустить программу на хосте.
func TestProxyBlocksCrossSiteStateChange(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
	}{
		{"чужой Origin на POST", http.MethodPost, "/qbittorrent/api/v2/app/setPreferences",
			map[string]string{"Origin": "https://evil.example"}},
		{"Sec-Fetch-Site: cross-site на POST", http.MethodPost, "/qbittorrent/api/v2/torrents/delete",
			map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"соседний поддомен на POST", http.MethodPost, "/qbittorrent/api/v2/torrents/delete",
			map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"GET к API с чужого сайта", http.MethodGet, "/qbittorrent/api/v2/torrents/pause",
			map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}},
		{"подресурсный GET с чужого сайта", http.MethodGet, "/qbittorrent/",
			map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, captured, _ := newProxyEnv(t)
			r := authorized(httptest.NewRequest(tc.method, tc.path, strings.NewReader("x=1")))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()

			p.ServeHTTP(w, r)

			if w.Code != http.StatusForbidden {
				t.Fatalf("код %d, ожидался 403", w.Code)
			}
			if captured.Path != "" {
				t.Fatalf("запрос дошёл до qBittorrent: %q", captured.Path)
			}
		})
	}
}

func TestProxyAllowsSameOriginAndDirectNavigation(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
	}{
		{"свой Origin", http.MethodPost, "/qbittorrent/api/v2/torrents/pause",
			map[string]string{"Origin": "https://inside.akiba.space", "Sec-Fetch-Site": "same-origin"}},
		{"ввод адреса вручную", http.MethodGet, "/qbittorrent/",
			map[string]string{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"}},
		{"переход с чужого сайта на интерфейс", http.MethodGet, "/qbittorrent/",
			map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}},
		{"старый браузер без Sec-Fetch", http.MethodGet, "/qbittorrent/", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, captured, _ := newProxyEnv(t)
			r := authorized(httptest.NewRequest(tc.method, tc.path, strings.NewReader("hashes=all")))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
			r.Header.Set("X-Forwarded-Proto", "https")
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()

			p.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("код %d, запрос должен был пройти", w.Code)
			}
			if captured.Path == "" {
				t.Fatal("запрос не дошёл до qBittorrent")
			}
		})
	}
}

// Сегменты ".." до бэкенда доходить не должны: бэкенд, который их
// нормализует, увидит адрес вне префикса и разъедется с проверкой на
// /api/v2/torrents/add.
func TestProxyRejectsDotSegments(t *testing.T) {
	for _, path := range []string{
		"/qbittorrent/%2e%2e/verify",
		"/qbittorrent/..%2fverify",
		"/qbittorrent/a/../../b",
		"/qbittorrent/./api/v2/app/version",
	} {
		t.Run(path, func(t *testing.T) {
			p, _, captured, _ := newProxyEnv(t)
			r := authorized(httptest.NewRequest(http.MethodGet, path, nil))
			w := httptest.NewRecorder()

			p.ServeHTTP(w, r)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("код %d, ожидался 400", w.Code)
			}
			if captured.Path != "" {
				t.Fatalf("путь дошёл до qBittorrent: %q", captured.Path)
			}
		})
	}
}

// В режиме bypass qBittorrent берёт адрес клиента из X-Forwarded-For.
// Оставив там IP браузера, мы заставили бы вносить в whitelist подсети
// резидентов вместо подсети шлюза — то есть открыть qBittorrent всей
// локальной сети без пароля.
func TestProxyDropsForwardedForInBypassMode(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Forwarded-For"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	base, _ := url.Parse("https://inside.akiba.space")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	bypass := qbit.NewProxy("/qbittorrent", target,
		qbit.NewClient(target, noRedirectClient(), "admin", "secret", false),
		&memoryTracker{}, &memoryAnnouncer{}, auth.HostPolicy{Base: base}, log)
	w := httptest.NewRecorder()
	bypass.ServeHTTP(w, authorized(httptest.NewRequest(http.MethodGet, "/qbittorrent/", nil)))
	if got := w.Body.String(); got != "" {
		t.Fatalf("X-Forwarded-For = %q, в режиме bypass он должен сниматься", got)
	}

	session := qbit.NewProxy("/qbittorrent", target,
		qbit.NewClient(target, noRedirectClient(), "admin", "secret", true),
		&memoryTracker{}, &memoryAnnouncer{}, auth.HostPolicy{Base: base}, log)
	w = httptest.NewRecorder()
	r := authorized(httptest.NewRequest(http.MethodGet, "/qbittorrent/", nil))
	r.RemoteAddr = "192.168.8.99:51234"
	// Цепочку, пришедшую от клиента, qBittorrent видеть не должен: с
	// включённой поддержкой реверс-прокси он читает её первый элемент, и
	// резидент отправлял бы в бан или в whitelist любой чужой адрес.
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	session.ServeHTTP(w, r)

	got := w.Body.String()
	if got == "" {
		t.Fatal("в режиме session X-Forwarded-For нужен qBittorrent для журналирования")
	}
	if got != "192.168.8.99" {
		t.Fatalf("X-Forwarded-For = %q, ожидался только адрес клиента шлюза", got)
	}
}

// qBittorrent сверяет X-Forwarded-Host со своим собственным адресом, даже
// когда «Reverse proxy support» в нём выключен, и отвечает 401 на любое
// другое значение — включая пустое. Проверено на 5.1.4. Пока заголовок
// уходил как есть, весь интерфейс отдавал 401 и никакой ошибки в журнале
// шлюза при этом не появлялось.
func TestProxyDropsForwardedHost(t *testing.T) {
	p, _, captured, _ := newProxyEnv(t)

	r := authorized(httptest.NewRequest(http.MethodGet, "/qbittorrent/api/v2/app/version", nil))
	r.Host = "inside.akiba.space"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if captured.Fwd != "" {
		t.Fatalf("до qBittorrent дошёл X-Forwarded-Host = %q, ожидалось, что его снимут", captured.Fwd)
	}
}

// Origin: null — это неизвестный источник (песочница iframe, документ data:,
// часть цепочек редиректов), а не свой. Исключение для него ничего не давало
// и снимало один слой защиты.
func TestProxyRejectsNullOrigin(t *testing.T) {
	p, tracker, _, _ := newProxyEnv(t)

	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		strings.NewReader("urls=magnet:?xt=urn:btih:"+strings.Repeat("a", 40))))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "null")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("код %d, ожидался 403", w.Code)
	}
	if len(tracker.all()) != 0 {
		t.Error("запрос с неизвестным источником всё же взят под наблюдение")
	}
}

// Сообщение в чат — та самая функция, ради которой всё затевалось, и до сих
// пор ни один тест не проверял, что оно вообще отправляется.
func TestProxyAnnouncesAddedTorrent(t *testing.T) {
	p, _, _, ann := newProxyEnv(t)

	magnet := "magnet:?xt=urn:btih:" + strings.Repeat("b", 40) + "&dn=Ubuntu"
	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		strings.NewReader("urls="+url.QueryEscape(magnet))))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.ServeHTTP(httptest.NewRecorder(), r)

	events := ann.wait(t, 1)
	if events[0].TorrentName != "Ubuntu" {
		t.Errorf("в чат ушло название %q", events[0].TorrentName)
	}
	if events[0].Username != "alice" {
		t.Errorf("в чат ушёл ник %q", events[0].Username)
	}
	if !strings.HasPrefix(events[0].Magnet, "magnet:?") {
		t.Errorf("магнит не передан: %q", events[0].Magnet)
	}
}

// Без опознанного резидента сообщать нечего: весь смысл в том, кто добавил.
func TestProxyDoesNotAnnounceWithoutUser(t *testing.T) {
	p, _, _, ann := newProxyEnv(t)

	r := httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		strings.NewReader("urls=magnet:?xt=urn:btih:"+strings.Repeat("c", 40)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.ServeHTTP(httptest.NewRecorder(), r)

	time.Sleep(50 * time.Millisecond)
	if got := ann.all(); len(got) != 0 {
		t.Fatalf("аноним попал в чат: %v", got)
	}
}

// За один запрос можно добавить до MaxRefs ссылок. Сообщение на каждую — это
// упор в ограничения Telegram и залитый чат.
func TestProxyCapsAnnouncements(t *testing.T) {
	p, _, _, ann := newProxyEnv(t)

	var links []string
	for i := 0; i < 30; i++ {
		links = append(links, fmt.Sprintf("magnet:?xt=urn:btih:%040x&dn=t%d", i, i))
	}
	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		strings.NewReader("urls="+url.QueryEscape(strings.Join(links, "\n")))))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.ServeHTTP(httptest.NewRecorder(), r)

	time.Sleep(150 * time.Millisecond)
	if got := len(ann.all()); got == 0 || got > 10 {
		t.Fatalf("в чат ушло %d сообщений: ожидалось немного, но не ноль", got)
	}
}

// Ссылка на .torrent по http приходит без хеша — сопоставить её с ответом
// qBittorrent нечем. Прокси всё равно передаёт её воркеру: отсев — его дело,
// и делать его в двух местах значило бы однажды развести правила.
func TestProxyHandsEveryParsedRefToTracker(t *testing.T) {
	p, tracker, _, _ := newProxyEnv(t)

	body := "urls=" + url.QueryEscape(
		"magnet:?xt=urn:btih:"+strings.Repeat("a", 40)+"\nhttp://tracker.example/file.torrent")
	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		strings.NewReader(body)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.ServeHTTP(httptest.NewRecorder(), r)

	items := tracker.all()
	if len(items) != 2 {
		t.Fatalf("воркеру передано %d торрентов, ожидалось 2: %+v", len(items), items)
	}
	var withHash, withoutHash int
	for _, it := range items {
		if it.TelegramID != "42424242" {
			t.Fatalf("торрент передан без адресата: %+v", it)
		}
		if it.InfoHash == "" {
			withoutHash++
		} else {
			withHash++
		}
	}
	if withHash != 1 || withoutHash != 1 {
		t.Fatalf("ожидались один торрент с хешем и один без: %+v", items)
	}
}

// Воркер необязателен: без него прокси обязан работать как обычный прокси.
func TestProxyWorksWithoutTracker(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	base, _ := url.Parse("https://inside.akiba.space")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := qbit.NewClient(target, http.DefaultClient, "", "", false)

	p := qbit.NewProxy("/qbittorrent", target, client, nil, nil,
		auth.HostPolicy{Base: base}, log)

	r := authorized(httptest.NewRequest(http.MethodPost, "/qbittorrent/api/v2/torrents/add",
		strings.NewReader("urls=magnet:?xt=urn:btih:"+strings.Repeat("a", 40))))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("код %d, ожидался 200", w.Code)
	}
}
