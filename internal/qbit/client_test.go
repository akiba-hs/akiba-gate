package qbit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/qbit"
)

// fakeQbit — минимальная имитация WebUI API qBittorrent.
type fakeQbit struct {
	logins   atomic.Int32
	password string
	sid      string
	// expireFirstCall заставляет первый защищённый запрос ответить 403,
	// как это делает qBittorrent с протухшей сессией.
	expireFirstCall atomic.Bool
	// loginDelay задерживает ответ на логин: нужен, чтобы отмена контекста
	// вызывающего успела произойти во время входа.
	loginDelay atomic.Int64

	infoMu   sync.Mutex
	torrents []qbit.TorrentInfo
	// infoBody, если задан, отдаётся вместо torrents — для проверки
	// поведения на некорректном ответе.
	infoBody string
}

// setTorrents заменяет список торрентов, который отдаёт фейк.
func (f *fakeQbit) setTorrents(items ...qbit.TorrentInfo) {
	f.infoMu.Lock()
	defer f.infoMu.Unlock()
	f.torrents = items
}

func (f *fakeQbit) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/auth/login", func(w http.ResponseWriter, r *http.Request) {
		f.logins.Add(1)
		if d := f.loginDelay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}
		_ = r.ParseForm()
		if r.FormValue("password") != f.password {
			_, _ = w.Write([]byte("Fails."))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: f.sid, Path: "/"})
		_, _ = w.Write([]byte("Ok."))
	})
	mux.HandleFunc("/api/v2/app/version", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("v5.0.0\n"))
	})
	mux.HandleFunc("/api/v2/torrents/info", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		f.infoMu.Lock()
		body, items := f.infoBody, append([]qbit.TorrentInfo(nil), f.torrents...)
		f.infoMu.Unlock()

		if body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		_ = json.NewEncoder(w).Encode(items)
	})
	return mux
}

func (f *fakeQbit) authorized(r *http.Request) bool {
	if f.expireFirstCall.CompareAndSwap(true, false) {
		return false
	}
	c, err := r.Cookie("SID")
	return err == nil && c.Value == f.sid
}

func newFake(t *testing.T, password string) (*fakeQbit, *url.URL) {
	t.Helper()
	f := &fakeQbit{password: password, sid: "sid-123"}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return f, u
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func TestClientLoginAndSessionCache(t *testing.T) {
	f, u := newFake(t, "secret")
	c := qbit.NewClient(u, noRedirectClient(), "admin", "secret", true)

	sid, err := c.SID(context.Background())
	if err != nil {
		t.Fatalf("SID: %v", err)
	}
	if sid != "sid-123" {
		t.Fatalf("SID = %q", sid)
	}
	// Второй вызов обязан взять сессию из кэша: логин в qBittorrent
	// ограничен по числу попыток, и лишние заходы приводят к бану по IP.
	if _, err := c.SID(context.Background()); err != nil {
		t.Fatalf("повторный SID: %v", err)
	}
	if got := f.logins.Load(); got != 1 {
		t.Fatalf("выполнено %d логинов, ожидался 1", got)
	}
}

func TestClientLoginRejectsWrongPassword(t *testing.T) {
	_, u := newFake(t, "secret")
	c := qbit.NewClient(u, noRedirectClient(), "admin", "wrong", true)

	if _, err := c.SID(context.Background()); err == nil {
		t.Fatal("неверный пароль принят")
	}
}

// В режиме bypass логиниться нельзя, даже если учётные данные заданы:
// лишние попытки входа приводят к бану по IP в самом qBittorrent.
func TestClientBypassModeDoesNotLogin(t *testing.T) {
	f, u := newFake(t, "secret")
	c := qbit.NewClient(u, noRedirectClient(), "admin", "secret", false)

	sid, err := c.SID(context.Background())
	if err != nil {
		t.Fatalf("SID: %v", err)
	}
	if sid != "" {
		t.Fatalf("в режиме bypass SID должен быть пустым, получено %q", sid)
	}
	if f.logins.Load() != 0 {
		t.Fatal("в режиме bypass логин не нужен")
	}
}

// Протухшая сессия должна восстанавливаться прозрачно для вызывающего кода.
func TestClientRelogsInOnForbidden(t *testing.T) {
	f, u := newFake(t, "secret")
	c := qbit.NewClient(u, noRedirectClient(), "admin", "secret", true)
	if _, err := c.SID(context.Background()); err != nil {
		t.Fatalf("SID: %v", err)
	}
	f.expireFirstCall.Store(true)

	// Любой авторизованный запрос годится: 403 ловится общим кодом.
	if _, err := c.TorrentsInfo(context.Background()); err != nil {
		t.Fatalf("TorrentsInfo после протухшей сессии: %v", err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("выполнено %d логинов, ожидалось 2 (второй после 403)", f.logins.Load())
	}
}

func TestClientTorrentsInfoParsesProgress(t *testing.T) {
	f, u := newFake(t, "secret")
	f.setTorrents(
		qbit.TorrentInfo{Hash: "AABB", Name: "Ubuntu 24.04", Progress: 1},
		qbit.TorrentInfo{Hash: "ccdd", Name: "Debian", Progress: 0.5},
	)
	c := qbit.NewClient(u, noRedirectClient(), "admin", "secret", true)

	items, err := c.TorrentsInfo(context.Background())
	if err != nil {
		t.Fatalf("TorrentsInfo: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("получено %+v", items)
	}
	if items[0].Hash != "AABB" || items[0].Progress != 1 {
		t.Fatalf("первый торрент разобран как %+v", items[0])
	}
	if !strings.Contains(items[0].Name, "Ubuntu") {
		t.Fatalf("имя = %q", items[0].Name)
	}
	if items[1].Progress != 0.5 {
		t.Fatalf("прогресс второго = %v", items[1].Progress)
	}
}

func TestClientTorrentsInfoFailsOnBrokenJSON(t *testing.T) {
	f, u := newFake(t, "secret")
	f.infoBody = "не json"
	c := qbit.NewClient(u, noRedirectClient(), "admin", "secret", true)

	if _, err := c.TorrentsInfo(context.Background()); err == nil {
		t.Fatal("битый JSON принят")
	}
}

// qBittorrent банит клиента по IP после нескольких неудачных входов.
// Одна загрузка WebUI — это десятки запросов к API, поэтому без паузы
// неверный пароль превращается в час недоступности.
func TestClientDoesNotHammerLoginAfterFailure(t *testing.T) {
	f, u := newFake(t, "secret")
	c := qbit.NewClient(u, noRedirectClient(), "admin", "wrong", true)

	for i := 0; i < 20; i++ {
		if _, err := c.SID(context.Background()); err == nil {
			t.Fatal("неверный пароль принят")
		}
	}
	if got := f.logins.Load(); got != 1 {
		t.Fatalf("выполнено %d попыток входа, ожидалась 1 до истечения паузы", got)
	}
}

func TestClientRetriesLoginAfterBackoff(t *testing.T) {
	f, u := newFake(t, "secret")
	c := qbit.NewClient(u, noRedirectClient(), "admin", "wrong", true)

	now := time.Now()
	c.SetClock(func() time.Time { return now })
	if _, err := c.SID(context.Background()); err == nil {
		t.Fatal("неверный пароль принят")
	}

	now = now.Add(time.Hour) // пауза истекла
	if _, err := c.SID(context.Background()); err == nil {
		t.Fatal("неверный пароль принят")
	}
	if got := f.logins.Load(); got != 2 {
		t.Fatalf("после паузы выполнено %d попыток, ожидалось 2", got)
	}
}

// Успешный вход должен снимать паузу, иначе после починки пароля шлюз
// продолжал бы отдавать старую ошибку ещё полминуты.
func TestClientClearsBackoffAfterSuccess(t *testing.T) {
	f, u := newFake(t, "secret")
	c := qbit.NewClient(u, noRedirectClient(), "admin", "secret", true)

	if _, err := c.SID(context.Background()); err != nil {
		t.Fatalf("SID: %v", err)
	}
	c.Invalidate()
	if _, err := c.SID(context.Background()); err != nil {
		t.Fatalf("повторный SID: %v", err)
	}
	if got := f.logins.Load(); got != 2 {
		t.Fatalf("выполнено %d логинов, ожидалось 2", got)
	}
}

// Сессия qBittorrent общая на всех, а контекст запроса умирает, как только
// браузер ушёл со страницы. Если логиниться в нём, одна такая отмена
// записывалась бы в паузу после неудачи и на тридцать секунд оставляла без
// сессии всех остальных — при полностью исправном qBittorrent.
func TestClientLoginSurvivesCallerCancellation(t *testing.T) {
	f, u := newFake(t, "secret")
	f.loginDelay.Store(int64(150 * time.Millisecond))
	c := qbit.NewClient(u, noRedirectClient(), "admin", "secret", true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // клиент ушёл ещё до того, как мы начали логиниться

	if _, err := c.SID(ctx); err != nil {
		t.Fatalf("отменённый контекст вызывающего не должен ломать логин: %v", err)
	}

	// И следующий запрос обслуживается сразу, а не упирается в паузу.
	sid, err := c.SID(context.Background())
	if err != nil {
		t.Fatalf("следующий SID: %v", err)
	}
	if sid == "" {
		t.Fatal("сессия пуста")
	}
}

// Ответ 403 бывает и системным — разъехавшийся Referer, запрет в настройках.
// Веб-интерфейс опрашивает API несколько раз в секунду, и без паузы шлюз
// логинился бы на каждый запрос: бесконечно, успешно и незаметно.
func TestClientThrottlesInvalidate(t *testing.T) {
	f, u := newFake(t, "secret")
	c := qbit.NewClient(u, noRedirectClient(), "admin", "secret", true)
	now := time.Now()
	c.SetClock(func() time.Time { return now })

	if _, err := c.SID(context.Background()); err != nil {
		t.Fatalf("SID: %v", err)
	}
	for i := 0; i < 20; i++ {
		c.Invalidate()
		if _, err := c.SID(context.Background()); err != nil {
			t.Fatalf("SID #%d: %v", i, err)
		}
	}
	if got := f.logins.Load(); got != 2 {
		t.Fatalf("выполнено %d логинов, ожидалось 2: первый и один после сброса", got)
	}

	// Прошло достаточно времени — сброс снова разрешён.
	now = now.Add(time.Minute)
	c.Invalidate()
	if _, err := c.SID(context.Background()); err != nil {
		t.Fatalf("SID после паузы: %v", err)
	}
	if got := f.logins.Load(); got != 3 {
		t.Fatalf("после паузы логинов %d, ожидалось 3", got)
	}
}
