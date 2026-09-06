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

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url %q: %v", raw, err)
	}
	return u
}

func newForwardAuth(t *testing.T, requireResident bool) (*auth.ForwardAuth, testsupport.KeyPair) {
	t.Helper()
	v, kp := newVerifier(t)
	return &auth.ForwardAuth{
		Verifier:        v,
		CookieName:      "token",
		AuthURL:         mustURL(t, "https://auth.akiba.space/"),
		PublicBaseURL:   mustURL(t, "https://inside.akiba.space"),
		RequireResident: requireResident,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, kp
}

// forwardRequest имитирует запрос, который шлёт Traefik в middleware forwardAuth.
func forwardRequest(t *testing.T, uri string, token string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	r.Header.Set("X-Forwarded-Uri", uri)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	if token != "" {
		r.AddCookie(&http.Cookie{Name: "token", Value: token})
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestForwardAuthAllowsResident(t *testing.T) {
	fa, kp := newForwardAuth(t, true)
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, forwardRequest(t, "/qbittorrent/", kp.ResidentToken(t), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("код %d, ожидался 200", w.Code)
	}
	if got := w.Header().Get(auth.HeaderUID); got != "tg42424242" {
		t.Fatalf("%s = %q", auth.HeaderUID, got)
	}
	if got := w.Header().Get(auth.HeaderUser); got != "alice" {
		t.Fatalf("%s = %q", auth.HeaderUser, got)
	}
	if got := w.Header().Get(auth.HeaderResident); got != "true" {
		t.Fatalf("%s = %q", auth.HeaderResident, got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("ответ ForwardAuth должен быть некэшируемым, получено %q", got)
	}
}

func TestForwardAuthRedirectsAnonymousToAuthService(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, forwardRequest(t, "/jellyfin/web/", "", nil))

	if w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался 302", w.Code)
	}
	loc := mustURL(t, w.Header().Get("Location"))
	if loc.Host != "auth.akiba.space" {
		t.Fatalf("редирект на %q", loc.Host)
	}
	// Возврат обязан вести ровно туда, куда резидент шёл.
	if got := loc.Query().Get("redirect_uri"); got != "https://inside.akiba.space/jellyfin/web/" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestForwardAuthRejectsInvalidTokenAsAnonymous(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, forwardRequest(t, "/", "не.токен.вовсе", nil))

	if w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался 302", w.Code)
	}
}

// Не-резидента нельзя отправлять на auth-service: токен валиден, и тот сразу
// вернёт резидента обратно — получится бесконечный цикл редиректов.
func TestForwardAuthSendsNonResidentToPortalNotToLogin(t *testing.T) {
	fa, kp := newForwardAuth(t, true)
	token := kp.Token(t, testsupport.TokenOptions{Username: "bob", IsResident: false})
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, forwardRequest(t, "/qbittorrent/", token, nil))

	if w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался 302", w.Code)
	}
	loc := mustURL(t, w.Header().Get("Location"))
	if loc.Host != "inside.akiba.space" {
		t.Fatalf("не-резидента увели на %q вместо портала", loc.Host)
	}
	if got := loc.Query().Get("error"); got != "not_resident" {
		t.Fatalf("error = %q", got)
	}
}

func TestForwardAuthAllowsNonResidentWhenPolicyDisabled(t *testing.T) {
	fa, kp := newForwardAuth(t, false)
	token := kp.Token(t, testsupport.TokenOptions{Username: "bob", IsResident: false})
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, forwardRequest(t, "/", token, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("код %d, ожидался 200", w.Code)
	}
	if got := w.Header().Get(auth.HeaderResident); got != "false" {
		t.Fatalf("%s = %q", auth.HeaderResident, got)
	}
}

// XHR-клиенту нужен 401, а не редирект: иначе фронтенд Jellyfin или
// qBittorrent молча уйдёт на чужой origin и упрётся в CORS.
func TestForwardAuthReturns401ForXHR(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, forwardRequest(t, "/qbittorrent/api/v2/sync/maindata", "",
		map[string]string{"X-Requested-With": "XMLHttpRequest"}))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("код %d, ожидался 401", w.Code)
	}
	if w.Header().Get("Location") == "" {
		t.Fatal("в 401 полезно оставить Location для клиента")
	}
}

func TestForwardAuthReturns401ForFetchNonNavigate(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, forwardRequest(t, "/qbittorrent/api/v2/app/version", "",
		map[string]string{"Sec-Fetch-Mode": "cors"}))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("код %d, ожидался 401", w.Code)
	}
}

// Самое опасное место схемы: клиент не должен уметь представиться чужим,
// прислав заголовки идентичности самостоятельно.
func TestForwardAuthOverwritesSpoofedIdentityHeaders(t *testing.T) {
	fa, kp := newForwardAuth(t, true)
	r := forwardRequest(t, "/", kp.ResidentToken(t), map[string]string{
		auth.HeaderUID:  "tg1",
		auth.HeaderUser: "admin",
	})
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, r)

	if got := r.Header.Get(auth.HeaderUID); got != "" {
		t.Fatalf("подделанный заголовок остался во входящем запросе: %q", got)
	}
	if got := w.Header().Get(auth.HeaderUID); got != "tg42424242" {
		t.Fatalf("в ответе %s = %q, ожидался настоящий резидент", auth.HeaderUID, got)
	}
}

func TestForwardAuthDropsSpoofedHeadersForAnonymous(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	r := forwardRequest(t, "/", "", map[string]string{auth.HeaderUID: "tg1"})
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, r)

	if w.Header().Get(auth.HeaderUID) != "" {
		t.Fatal("анонимному запросу выданы заголовки идентичности")
	}
}

func TestOriginalURLFallsBackWithoutForwardedHost(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/verify", nil)
	got := auth.OriginalURL(r, mustURL(t, "https://inside.akiba.space"))
	if got != "https://inside.akiba.space/" {
		t.Fatalf("получено %q", got)
	}
}

func TestOriginalURLNormalizesURI(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/verify", nil)
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	r.Header.Set("X-Forwarded-Uri", "jellyfin/web/")

	if got := auth.OriginalURL(r, nil); got != "https://inside.akiba.space/jellyfin/web/" {
		t.Fatalf("получено %q", got)
	}
}

// X-Forwarded-Host приходит извне. Без проверки по нему собирается ссылка
// вида auth.akiba.space/?redirect_uri=https://evil.example — внешне
// легитимная, и её можно подсунуть жертве.
func TestForwardAuthRejectsForeignReturnHost(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	r := forwardRequest(t, "/", "", nil)
	r.Header.Set("X-Forwarded-Host", "evil.example")
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, r)

	loc := mustURL(t, w.Header().Get("Location"))
	if got := loc.Query().Get("redirect_uri"); got != "https://inside.akiba.space/" {
		t.Fatalf("redirect_uri = %q, ожидался откат на портал", got)
	}
}

func TestForwardAuthAllowsConfiguredExtraHost(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	fa.AllowedHosts = []string{"nextcloud.akiba.space"}
	r := forwardRequest(t, "/_akiba-sso", "", nil)
	r.Header.Set("X-Forwarded-Host", "nextcloud.akiba.space")
	w := httptest.NewRecorder()

	fa.ServeHTTP(w, r)

	loc := mustURL(t, w.Header().Get("Location"))
	if got := loc.Query().Get("redirect_uri"); got != "https://nextcloud.akiba.space/_akiba-sso" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestGuardRejectsForeignReturnHost(t *testing.T) {
	fa, _ := newForwardAuth(t, true)
	h := fa.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest(http.MethodGet, "https://evil.example/sso/jellyfin", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	loc := mustURL(t, w.Header().Get("Location"))
	if strings.Contains(loc.Query().Get("redirect_uri"), "evil.example") {
		t.Fatalf("redirect_uri = %q", loc.Query().Get("redirect_uri"))
	}
}

// То же ограничение auth-service действует и для forwardAuth, и для Guard:
// адрес возврата обязан быть без порта, иначе вход заканчивается 400.
// Путь исходного запроса при этом теряется — см. пояснение у ReturnBase.
func TestForwardAuthAppliesReturnBase(t *testing.T) {
	kp := testsupport.NewKeyPair(t)
	v, err := auth.NewVerifier(kp.PublicPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	base := &url.URL{Scheme: "http", Host: "inside.akiba.space:8080"}
	fa := &auth.ForwardAuth{
		Verifier:        v,
		CookieName:      "token",
		AuthURL:         &url.URL{Scheme: "https", Host: "auth.akiba.space"},
		PublicBaseURL:   base,
		ReturnBase:      &url.URL{Scheme: "http", Host: "inside.akiba.space"},
		RequireResident: true,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space:8080/verify", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space:8080")
	r.Header.Set("X-Forwarded-Uri", "/qbittorrent/")
	w := httptest.NewRecorder()
	fa.ServeHTTP(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, url.QueryEscape("http://inside.akiba.space/")) {
		t.Errorf("Location = %q, ожидался настроенный адрес возврата", loc)
	}
	if strings.Contains(loc, "%3A8080") {
		t.Errorf("в адрес возврата попал порт: %q", loc)
	}
	// Путь исходного запроса намеренно не переносится: адрес возврата может
	// вести на постороннюю страницу, и чужой путь привёл бы туда на 404.
	if strings.Contains(loc, "qbittorrent") {
		t.Errorf("в адрес возврата попал путь исходного запроса: %q", loc)
	}
}
