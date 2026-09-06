package jellyfin_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/jellyfin"
)

// fakeJellyfin имитирует ровно те эндпоинты, которыми пользуется шлюз.
type fakeJellyfin struct {
	auths     atomic.Int32
	validates atomic.Int32
	password  string
	token     atomic.Value // string
	// tokenValid управляет ответом /Users/{id}: так проверяется поведение
	// при протухшем токене.
	tokenValid atomic.Bool
}

func newFakeJellyfin(t *testing.T, password string) (*fakeJellyfin, *url.URL) {
	t.Helper()
	f := &fakeJellyfin{password: password}
	f.token.Store("token-1")
	f.tokenValid.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/System/Info/Public", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Id":"server-id","ServerName":"akiba","Version":"10.11.11"}`))
	})
	mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
		f.auths.Add(1)
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), f.password) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "MediaBrowser ") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"AccessToken":"` + f.token.Load().(string) +
			`","ServerId":"server-id","User":{"Id":"user-id","Name":"residents"}}`))
	})
	mux.HandleFunc("/Users/user-id", func(w http.ResponseWriter, r *http.Request) {
		f.validates.Add(1)
		if !f.tokenValid.Load() || !strings.Contains(r.Header.Get("Authorization"), f.token.Load().(string)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"Id":"user-id"}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return f, u
}

// newSSO собирает обработчик автовхода с политикой публичных хостов.
//
// Адрес Jellyfin сюда не передаётся: страница автовхода целиком собирается на
// сервере и к самому Jellyfin не ходит — за неё это делает браузер.
func newSSO(t *testing.T) *jellyfin.SSOHandler {
	t.Helper()
	base, err := url.Parse("https://inside.akiba.space")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return &jellyfin.SSOHandler{
		BasePath: "/jellyfin",
		Hosts:    auth.HostPolicy{Base: base},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestClientAuthenticatesAndCachesSession(t *testing.T) {
	f, u := newFakeJellyfin(t, "pass")
	c := jellyfin.NewClient(u, http.DefaultClient, "residents", "pass")

	s, err := c.Session(context.Background())
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if s.AccessToken != "token-1" || s.UserID != "user-id" {
		t.Fatalf("сессия = %+v", s)
	}

	// Повторный вызов не должен логиниться заново: иначе в Jellyfin
	// накапливаются устройства и сессии.
	if _, err := c.Session(context.Background()); err != nil {
		t.Fatalf("повторный Session: %v", err)
	}
	if got := f.auths.Load(); got != 1 {
		t.Fatalf("выполнено %d логинов, ожидался 1", got)
	}
	if f.validates.Load() == 0 {
		t.Fatal("кэшированная сессия должна проверяться перед выдачей")
	}
}

func TestClientReauthenticatesWhenTokenExpired(t *testing.T) {
	f, u := newFakeJellyfin(t, "pass")
	c := jellyfin.NewClient(u, http.DefaultClient, "residents", "pass")
	if _, err := c.Session(context.Background()); err != nil {
		t.Fatalf("Session: %v", err)
	}

	f.tokenValid.Store(false)
	f.token.Store("token-2")
	f.tokenValid.Store(true)

	s, err := c.Session(context.Background())
	if err != nil {
		t.Fatalf("Session после протухания: %v", err)
	}
	if s.AccessToken != "token-2" {
		t.Fatalf("токен = %q, ожидался обновлённый", s.AccessToken)
	}
	if f.auths.Load() != 2 {
		t.Fatalf("выполнено %d логинов, ожидалось 2", f.auths.Load())
	}
}

func TestClientRejectsWrongPassword(t *testing.T) {
	_, u := newFakeJellyfin(t, "pass")
	c := jellyfin.NewClient(u, http.DefaultClient, "residents", "wrong")

	if _, err := c.Session(context.Background()); err == nil {
		t.Fatal("неверный пароль принят")
	}
}

func TestSSOHandlerRendersCredentialsAndRedirect(t *testing.T) {
	h := newSSO(t)

	r := httptest.NewRequest(http.MethodGet, "/sso/jellyfin", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("код %d", w.Code)
	}
	body := w.Body.String()
	// Токена в странице быть не должно: его получает сам браузер, обменяв
	// подтверждённый секрет быстрого подключения. Проверяем, что страница
	// умеет провести весь обмен и знает, куда потом уйти.
	if strings.Contains(body, "token-1") {
		t.Fatal("в страницу попал служебный токен, хотя вход делает браузер")
	}
	for _, want := range []string{
		"jellyfin_credentials", "_deviceId2", "/QuickConnect/Initiate",
		"/Users/AuthenticateWithQuickConnect", jellyfin.QuickConnectApprovePath,
		"https://inside.akiba.space/jellyfin", "/jellyfin/web/",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("в странице нет %q:\n%s", want, body)
		}
	}
	// Страница выдаёт доступ и персональна — кэшировать её нельзя.
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if w.Header().Get("X-Robots-Tag") == "" {
		t.Fatal("страница должна быть закрыта от индексации")
	}
}

// Адрес сервера в localStorage обязан быть публичным: с внутренним адресом
// контейнера браузер резидента никуда не попадёт.
func TestSSOHandlerUsesPublicAddress(t *testing.T) {
	_, u := newFakeJellyfin(t, "pass")
	h := newSSO(t)
	r := httptest.NewRequest(http.MethodGet, "/sso/jellyfin", nil)
	r.Host = "inside.akiba.space"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if strings.Contains(w.Body.String(), u.Host) {
		t.Fatalf("в страницу попал внутренний адрес %s", u.Host)
	}
}

// Страница рендерится, даже когда Jellyfin лежит: она ничего не спрашивает
// у него на сервере. Недоступность обнаружит уже браузер и покажет причину
// прямо на этой странице, а не пустой 502 без объяснений.
func TestSSOHandlerRendersWithoutTalkingToJellyfin(t *testing.T) {
	h := newSSO(t)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sso/jellyfin", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("код %d, ожидался 200", w.Code)
	}
}

// По адресу из localStorage веб-клиент Jellyfin ходит с полученным токеном.
// Подставленный Host отправил бы и запросы, и токен на хост злоумышленника,
// поэтому адрес берётся только из проверенного origin.
func TestSSOHandlerRejectsForeignHost(t *testing.T) {
	h := newSSO(t)

	r := httptest.NewRequest(http.MethodGet, "/sso/jellyfin", nil)
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	body := w.Body.String()
	if strings.Contains(body, "evil.example") {
		t.Fatalf("посторонний хост записан в localStorage:\n%s", body)
	}
	if !strings.Contains(body, "https://inside.akiba.space/jellyfin") {
		t.Fatal("не выполнен откат на канонический адрес")
	}
}

// Из локальной сети шлюз открывают по http; подмена схемы на https увела бы
// веб-клиент Jellyfin на другой origin и сломала бы его запросы.
func TestSSOHandlerKeepsRequestScheme(t *testing.T) {
	h := newSSO(t)

	r := httptest.NewRequest(http.MethodGet, "/sso/jellyfin", nil)
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	r.Header.Set("X-Forwarded-Proto", "http")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if !strings.Contains(w.Body.String(), "http://inside.akiba.space/jellyfin") {
		t.Fatalf("схема запроса не сохранена:\n%s", w.Body.String())
	}
}
