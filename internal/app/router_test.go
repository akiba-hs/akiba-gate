package app_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/app"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/jellyfin"
	"github.com/akiba-hs/akiba-gate/internal/portal"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url %q: %v", raw, err)
	}
	return u
}

// marker — обработчик-заглушка, отмечающий, что маршрут сработал.
func marker(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, name)
	})
}

func newRouter(t *testing.T) (http.Handler, testsupport.KeyPair) {
	t.Helper()
	return newRouterWithLog(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func newRouterWithLog(t *testing.T, log *slog.Logger) (http.Handler, testsupport.KeyPair) {
	t.Helper()
	return newRouterWithAccess(t, log, access.All())
}

// newRouterWithAccess собирает шлюз с заданным набором разрешённых сервисов.
func newRouterWithAccess(t *testing.T, log *slog.Logger, allowed []access.ID) (http.Handler, testsupport.KeyPair) {
	t.Helper()
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
		Log:             log,
	}
	policy := access.ResidentPolicy{Services: allowed}
	return app.NewRouter(app.Deps{
		Log:         log,
		ForwardAuth: fa,
		Policy:      policy,
		Portal: &portal.Handler{
			Verifier: v, CookieName: "token",
			AuthURL: mustURL(t, "https://auth.akiba.space"),
			Hosts:   auth.HostPolicy{Base: base},
			Policy:  policy,
			Catalog: access.Catalog{
				JellyfinURL:  "/sso/jellyfin",
				QbitURL:      "/qbittorrent/",
				NextcloudURL: "/nextcloud",
				AdminURL:     "/admin",
			},
			Texts:    testsupport.StaticTexts{},
			Audience: auth.NewSeen(),
			Log:      log,
		},
		JellyfinSSO:      marker("jellyfin-sso"),
		JellyfinProxy:    marker("jellyfin-proxy"),
		JellyfinBasePath: "/jellyfin",
		JellyfinConnect:  marker("jellyfin-connect"),
		JellyfinApprove:  marker("jellyfin-approve"),
		QbitProxy:        marker("qbit-proxy"),
		QbitBasePath:     "/qbittorrent",
		NextcloudSSO:     marker("nextcloud-sso"),
		NextcloudRedeem:  marker("nextcloud-redeem"),
		Admin:            marker("admin"),
		UserPic:          marker("userpic"),
		TorrentLink:      marker("trrntlink"),
	}), kp
}

func request(t *testing.T, h http.Handler, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Accept", "text/html")
	if token != "" {
		r.AddCookie(&http.Cookie{Name: "token", Value: token})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHealthzIsPublic(t *testing.T) {
	h, _ := newRouter(t)
	w := request(t, h, "https://inside.akiba.space/healthz", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("код %d, тело %q", w.Code, w.Body.String())
	}
}

func TestPortalIsPublic(t *testing.T) {
	h, _ := newRouter(t)
	w := request(t, h, "https://inside.akiba.space/", "")
	if w.Code != http.StatusOK {
		t.Fatalf("код %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "/sso/jellyfin") {
		t.Fatal("анонимному посетителю показаны ссылки")
	}
}

// Каждый защищённый маршрут обязан требовать токен: это ровно тот список,
// который нельзя случайно оставить открытым.
func TestProtectedRoutesRequireAuth(t *testing.T) {
	h, _ := newRouter(t)
	targets := []string{
		"https://inside.akiba.space/sso/jellyfin",
		"https://inside.akiba.space/nextcloud",
		"https://inside.akiba.space/qbittorrent",
		"https://inside.akiba.space/qbittorrent/api/v2/app/version",
		"https://inside.akiba.space/jellyfin/web/",
		"https://inside.akiba.space" + jellyfin.QuickConnectPath,
		"https://inside.akiba.space/nextcloud",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			w := request(t, h, target, "")
			if w.Code != http.StatusFound {
				t.Fatalf("код %d, ожидался редирект на вход", w.Code)
			}
			if !strings.Contains(w.Header().Get("Location"), "auth.akiba.space") {
				t.Fatalf("Location = %q", w.Header().Get("Location"))
			}
		})
	}
}

func TestProtectedRoutesWorkForResident(t *testing.T) {
	h, kp := newRouter(t)
	token := kp.ResidentToken(t)

	cases := map[string]string{
		"https://inside.akiba.space/sso/jellyfin":                   "jellyfin-sso",
		"https://inside.akiba.space/qbittorrent/api/v2/app/version": "qbit-proxy",
		"https://inside.akiba.space/jellyfin/web/":                  "jellyfin-proxy",
		"https://inside.akiba.space" + jellyfin.QuickConnectPath:    "jellyfin-connect",
		"https://inside.akiba.space/nextcloud":                      "nextcloud-sso",
	}
	for target, want := range cases {
		t.Run(target, func(t *testing.T) {
			w := request(t, h, target, token)
			if w.Body.String() != want {
				t.Fatalf("код %d, тело %q, ожидалось %q", w.Code, w.Body.String(), want)
			}
		})
	}
}

func TestVerifyEndpointAnswersForwardAuth(t *testing.T) {
	h, kp := newRouter(t)
	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	r.Header.Set("X-Forwarded-Uri", "/qbittorrent/")
	r.AddCookie(&http.Cookie{Name: "token", Value: kp.ResidentToken(t)})
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("код %d", w.Code)
	}
	if w.Header().Get(auth.HeaderUID) != "tg42424242" {
		t.Fatalf("%s = %q", auth.HeaderUID, w.Header().Get(auth.HeaderUID))
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	h, kp := newRouter(t)
	if w := request(t, h, "https://inside.akiba.space/такого-нет", kp.ResidentToken(t)); w.Code != http.StatusNotFound {
		t.Fatalf("код %d", w.Code)
	}
}

func TestSecurityHeadersArePresent(t *testing.T) {
	h, _ := newRouter(t)
	w := request(t, h, "https://inside.akiba.space/", "")
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("нет X-Content-Type-Options")
	}
}

func TestPanicInHandlerDoesNotKillGate(t *testing.T) {
	kp := testsupport.NewKeyPair(t)
	v, _ := auth.NewVerifier(kp.PublicPEM)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fa := &auth.ForwardAuth{
		Verifier: v, CookieName: "token",
		AuthURL:       mustURL(t, "https://auth.akiba.space"),
		PublicBaseURL: mustURL(t, "https://inside.akiba.space"),
		AllowedHosts:  []string{"nextcloud.akiba.space"},
		Log:           log,
	}
	policy := access.ResidentPolicy{Services: access.All()}
	h := app.NewRouter(app.Deps{
		Log: log, ForwardAuth: fa, Policy: policy,
		Portal: &portal.Handler{Verifier: v, CookieName: "token",
			AuthURL:  mustURL(t, "https://auth.akiba.space"),
			Hosts:    auth.HostPolicy{Base: mustURL(t, "https://inside.akiba.space")},
			Policy:   policy,
			Texts:    testsupport.StaticTexts{},
			Audience: auth.NewSeen(),
			Log:      log},
		JellyfinSSO: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("бум") }),
		QbitProxy:   marker("qbit"), QbitBasePath: "/qbittorrent",
	})

	w := request(t, h, "https://inside.akiba.space/sso/jellyfin", kp.ResidentToken(t))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("код %d, ожидался 500 вместо падения процесса", w.Code)
	}
}

// Подтверждение кода выдаёт рабочую сессию Jellyfin, поэтому маршрут обязан
// быть за Guard, как и всё остальное.
func TestJellyfinApproveRequiresAuth(t *testing.T) {
	h, kp := newRouter(t)

	r := httptest.NewRequest(http.MethodPost,
		"https://inside.akiba.space"+jellyfin.QuickConnectApprovePath, strings.NewReader(`{"code":"1"}`))
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался редирект на вход", w.Code)
	}

	r = httptest.NewRequest(http.MethodPost,
		"https://inside.akiba.space"+jellyfin.QuickConnectApprovePath, strings.NewReader(`{"code":"1"}`))
	r.AddCookie(&http.Cookie{Name: "token", Value: kp.ResidentToken(t)})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Body.String() != "jellyfin-approve" {
		t.Fatalf("тело %q", w.Body.String())
	}
}

// /whoami открыт намеренно: он отвечает только про самого спрашивающего, и
// вкладка портала должна опрашивать его до входа.
func TestWhoAmIIsPublic(t *testing.T) {
	h, _ := newRouter(t)
	w := request(t, h, "https://inside.akiba.space/whoami", "")

	if w.Code != http.StatusOK {
		t.Fatalf("код %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"authenticated":false`) {
		t.Fatalf("тело %q", w.Body.String())
	}
}

// Скрыть карточку недостаточно: адрес сервиса легко набрать руками, поэтому
// право проверяется и на маршруте.
func TestRoutesRespectServiceAccess(t *testing.T) {
	h, kp := newRouterWithAccess(t, slog.New(slog.NewTextHandler(io.Discard, nil)),
		[]access.ID{access.Jellyfin})
	token := kp.ResidentToken(t)

	allowed := request(t, h, "https://inside.akiba.space/jellyfin/web/", token)
	if allowed.Body.String() != "jellyfin-proxy" {
		t.Fatalf("разрешённый сервис не открылся: тело %q", allowed.Body.String())
	}

	for _, target := range []string{
		"https://inside.akiba.space/qbittorrent/",
		"https://inside.akiba.space/nextcloud",
	} {
		w := request(t, h, target, token)
		if w.Code != http.StatusForbidden {
			t.Errorf("закрытый сервис %s отдал код %d, ожидался 403", target, w.Code)
		}
	}
}

// Ссылку из чата открывают в групповом чате, где куки шлюза нет ни у кого.
func TestTorrentLinkIsPublic(t *testing.T) {
	h, _ := newRouter(t)
	w := request(t, h, "https://inside.akiba.space"+tgnotify.TorrentLinkPath+"?l=x", "")

	if w.Body.String() != "trrntlink" {
		t.Fatalf("тело %q, переход по ссылке должен работать без авторизации", w.Body.String())
	}
}

// Аватарки — прокси к чужому домену, и открытым он быть не должен.
func TestUserPicRequiresAuth(t *testing.T) {
	h, kp := newRouter(t)

	if w := request(t, h, "https://inside.akiba.space/userpic/320/a.jpg", ""); w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался редирект на вход", w.Code)
	}
	if w := request(t, h, "https://inside.akiba.space/userpic/320/a.jpg", kp.ResidentToken(t)); w.Body.String() != "userpic" {
		t.Fatalf("тело %q", w.Body.String())
	}
}

// Настоящий запрос <img> — это не навигация: браузер помечает его
// Sec-Fetch-Mode: no-cors, и редирект на auth.akiba.space такому запросу
// бесполезен. Шлюз обязан ответить 401, а не картинкой и не 302 — иначе
// фактическое поведение расходится с тем, что написано в README.
func TestUserPicRejectsAnonymousImageRequest(t *testing.T) {
	h, _ := newRouter(t)

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/userpic/320/a.jpg", nil)
	r.Header.Set("Accept", "image/*")
	r.Header.Set("Sec-Fetch-Mode", "no-cors")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("код %d, ожидался 401", w.Code)
	}
	if strings.Contains(w.Body.String(), "userpic") {
		t.Fatal("аноним получил картинку")
	}
}

// Nextcloud не развёрнут: вместо него заглушка, а не пустая страница.
func TestNextcloudServesStub(t *testing.T) {
	h, kp := newRouter(t)
	w := request(t, h, "https://inside.akiba.space/nextcloud", kp.ResidentToken(t))

	if w.Body.String() != "nextcloud-sso" {
		t.Fatalf("тело %q", w.Body.String())
	}
}
