package auth_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

func TestGuardPassesClaimsToHandler(t *testing.T) {
	fa, kp := newForwardAuth(t, true)
	var seen *auth.Claims
	h := fa.Guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, _ = auth.FromContext(r.Context())
	}))

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/sso/jellyfin", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: kp.ResidentToken(t)})
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen == nil {
		t.Fatal("обработчик не получил claims")
	}
	if seen.UID() != "tg42424242" {
		t.Fatalf("UID = %q", seen.UID())
	}
}

// Guard — вторая линия обороны: он проверяет куку сам и не верит заголовкам,
// которые мог проставить неправильно настроенный прокси.
func TestGuardIgnoresSpoofedHeadersWithoutCookie(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	called := false
	h := fa.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/sso/jellyfin", nil)
	r.Header.Set(auth.HeaderUID, "tg1")
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if called {
		t.Fatal("обработчик вызван без валидного токена")
	}
	if w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался 302 на вход", w.Code)
	}
}

func TestGuardBuildsRedirectFromDirectRequest(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	h := fa.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/sso/jellyfin?x=1", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	loc := mustURL(t, w.Header().Get("Location"))
	if got := loc.Query().Get("redirect_uri"); got != "https://inside.akiba.space/sso/jellyfin?x=1" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestGuardSendsNonResidentToPortal(t *testing.T) {
	fa, kp := newForwardAuth(t, true)
	h := fa.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("не-резидент не должен доходить до обработчика")
	}))

	token := kp.Token(t, testsupport.TokenOptions{Username: "bob", IsResident: false})
	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/nextcloud", nil)
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: "token", Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("код %d", w.Code)
	}
	if mustURL(t, w.Header().Get("Location")).Query().Get("error") != "not_resident" {
		t.Fatalf("Location = %q", w.Header().Get("Location"))
	}
}

// Guard строит ссылку входа в обход forwardAuth, поэтому настроенный адрес
// возврата обязан применяться и здесь. Первая версия правки этот путь
// пропустила: портал уходил на auth корректно, а любая защищённая ссылка —
// со старым адресом и портом, то есть снова в 400.
func TestGuardAppliesReturnBase(t *testing.T) {
	kp := testsupport.NewKeyPair(t)
	v, err := auth.NewVerifier(kp.PublicPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	fa := &auth.ForwardAuth{
		Verifier:        v,
		CookieName:      "token",
		AuthURL:         &url.URL{Scheme: "https", Host: "auth.akiba.space"},
		PublicBaseURL:   &url.URL{Scheme: "http", Host: "inside.akiba.space:8080"},
		ReturnBase:      &url.URL{Scheme: "https", Host: "auth.akiba.space"},
		RequireResident: true,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	h := fa.Guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space:8080/torrents", nil)
	r.Host = "inside.akiba.space:8080"
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	loc := w.Header().Get("Location")
	if strings.Contains(loc, "%3A8080") {
		t.Errorf("в адрес возврата попал порт, auth-service отвергнет его: %q", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("https://auth.akiba.space/")) {
		t.Errorf("Location = %q, ожидался настроенный адрес возврата", loc)
	}
}

// Форма запроса, которая на самом деле приходит за Traefik: X-Forwarded-Host
// он ставит всегда, а X-Forwarded-Uri — только внутри подзапроса forwardAuth.
// Пока ветка восстановления адреса включалась на Host, она в проде не
// срабатывала никогда: резидент после входа возвращался на портал вместо
// страницы, куда шёл.
func TestGuardKeepsDeepLinkBehindProxy(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	h := fa.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/qbittorrent/", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	r.Header.Set("X-Forwarded-Proto", "https")
	// X-Forwarded-Uri намеренно отсутствует — это обычный проксируемый запрос.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, url.QueryEscape("https://inside.akiba.space/qbittorrent/")) {
		t.Fatalf("Location = %q, адрес исходной страницы потерян", loc)
	}
}

// Заголовки идентичности шлюз проставляет только в ответе forwardAuth.
// Во входящем запросе им делать нечего: обработчики берут токен из контекста,
// а проставленные заголовки пришлось бы снимать в каждом прокси.
func TestGuardDoesNotInjectIdentityHeaders(t *testing.T) {
	fa, kp := newForwardAuth(t, true)
	var seen string
	h := fa.Guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get(auth.HeaderUID)
	}))

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/qbittorrent/", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: kp.ResidentToken(t)})
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen != "" {
		t.Fatalf("во входящий запрос подставлен %s = %q", auth.HeaderUID, seen)
	}
}

// Seen нужен, чтобы «резидент авторизовался» попадало в журнал один раз,
// а не на каждый его запрос.
func TestSeenReportsOnlyFirstEncounter(t *testing.T) {
	s := auth.NewSeen()
	if !s.First("tg1") {
		t.Fatal("первая встреча не отмечена")
	}
	if s.First("tg1") {
		t.Fatal("повторная встреча принята за первую")
	}
	if !s.First("tg2") {
		t.Fatal("другой резидент не отмечен")
	}
	if s.First("") {
		t.Fatal("пустой идентификатор принят")
	}
}

// X-Forwarded-Uri без X-Forwarded-Host давал адрес вида "https:///путь":
// auth-service отвергал его с 400, и в журнале шлюза не оставалось ничего.
func TestGuardBuildsValidURLWithoutForwardedHost(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	h := fa.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/qbittorrent/", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-Uri", "/qbittorrent/")
	// X-Forwarded-Host намеренно отсутствует.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	loc := w.Header().Get("Location")
	if strings.Contains(loc, "%3A%2F%2F%2F") || strings.Contains(loc, ":///") {
		t.Fatalf("собран адрес без хоста: %q", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("https://inside.akiba.space/qbittorrent/")) {
		t.Fatalf("Location = %q", loc)
	}
}

// Схему возврата берём из запроса, а не из PUBLIC_BASE_URL.
//
// Traefik ходит к шлюзу по http, поэтому r.TLS у настоящего запроса всегда
// nil. Подставляя схему портала, шлюз возвращал резидента из локальной сети
// с http на https — на другой origin, где нет ни его сессии Jellyfin в
// localStorage, ни совпадения Origin для qBittorrent.
func TestGuardKeepsRequestSchemeOnRedirect(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	fa.AllowedHosts = []string{"inside.akiba.space"}
	h := fa.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	// Обычный проксируемый запрос: X-Forwarded-Uri Traefik ставит только в
	// подзапросе forwardAuth, здесь его нет.
	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/qbittorrent/", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, url.QueryEscape("http://inside.akiba.space/qbittorrent/")) {
		t.Fatalf("схема запроса не сохранена; Location = %q", loc)
	}
}

// Администратор из конфигурации не должен запираться снаружи собственной
// системы. Остальной код исходит ровно из этого: политика выдаёт ему все
// сервисы даже при недоступной базе, сверка отказывается его удалять. Если бы
// Guard отвергал его за выход из чата, все эти гарантии были бы враньём.
func TestGuardLetsRootAdminInWithoutResidency(t *testing.T) {
	kp := testsupport.NewKeyPair(t)
	v, err := auth.NewVerifier(kp.PublicPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	base := mustURL(t, "https://inside.akiba.space")
	fa := &auth.ForwardAuth{
		Verifier:        v,
		CookieName:      "token",
		AuthURL:         mustURL(t, "https://auth.akiba.space"),
		PublicBaseURL:   base,
		RequireResident: true,
		RootAdmin:       "270369579",
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// Токен администратора, вышедшего из чата резидентов.
	token := kp.Token(t, testsupport.TokenOptions{
		TelegramID: "270369579", Username: "ilvesbogdan", IsResident: false,
	})

	reached := false
	h := fa.Guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		if claims, ok := auth.FromContext(r.Context()); !ok || claims.TelegramID != "270369579" {
			t.Errorf("в контексте не тот резидент: %+v", claims)
		}
	}))

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/admin", nil)
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: "token", Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !reached {
		t.Fatalf("администратор не пропущен, код ответа %d", w.Code)
	}

	// А обычный не-резидент по-прежнему не проходит.
	other := kp.Token(t, testsupport.TokenOptions{TelegramID: "999", IsResident: false})
	reached = false
	r2 := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/admin", nil)
	r2.Header.Set("Accept", "text/html")
	r2.AddCookie(&http.Cookie{Name: "token", Value: other})
	h.ServeHTTP(httptest.NewRecorder(), r2)
	if reached {
		t.Fatal("исключение для администратора распространилось на всех")
	}
}
