package app_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/admin"
	"github.com/akiba-hs/akiba-gate/internal/app"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/portal"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

// grantBook — выданные права, которые можно менять между запросами: ровно то,
// что делает администратор галочками.
type grantBook struct {
	mu     sync.Mutex
	byUser map[string][]string
}

func (g *grantBook) ResidentServices(_ context.Context, id string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.byUser[id]...), nil
}

func (g *grantBook) set(id string, services ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.byUser[id] = services
}

const rootAdminID = "270369579"

// newGuardedRouter собирает роутер с персональными правами из grantBook.
func newGuardedRouter(t *testing.T) (http.Handler, *grantBook, testsupport.KeyPair) {
	t.Helper()
	kp := testsupport.NewKeyPair(t)
	v, err := auth.NewVerifier(kp.PublicPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	base := mustURL(t, "https://inside.akiba.space")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	grants := &grantBook{byUser: map[string][]string{}}
	policy := access.StorePolicy{Grants: grants, RootAdmin: rootAdminID}

	fa := &auth.ForwardAuth{
		Verifier:        v,
		CookieName:      "token",
		AuthURL:         mustURL(t, "https://auth.akiba.space"),
		PublicBaseURL:   base,
		RequireResident: true,
		Log:             log,
	}
	catalog := access.Catalog{
		JellyfinURL:  "/sso/jellyfin",
		QbitURL:      "/qbittorrent/",
		NextcloudURL: "/nextcloud",
		AdminURL:     admin.Path,
	}
	return app.NewRouter(app.Deps{
		Log:         log,
		ForwardAuth: fa,
		Policy:      policy,
		Portal: &portal.Handler{
			Verifier: v, CookieName: "token",
			AuthURL: mustURL(t, "https://auth.akiba.space"),
			Hosts:   auth.HostPolicy{Base: base},
			Policy:  policy, Catalog: catalog,
			Texts:    testsupport.StaticTexts{},
			Audience: auth.NewSeen(),
			Log:      log,
		},
		JellyfinSSO:      marker("jellyfin-sso"),
		JellyfinProxy:    marker("jellyfin-proxy"),
		JellyfinBasePath: "/jellyfin",
		QbitProxy:        marker("qbit-proxy"),
		QbitBasePath:     "/qbittorrent",
		NextcloudSSO:     marker("nextcloud-sso"),
		Admin:            marker("admin"),
	}), grants, kp
}

// token выпускает куку резидента с заданным Telegram-ID.
func token(t *testing.T, kp testsupport.KeyPair, id string) string {
	t.Helper()
	return kp.Token(t, testsupport.TokenOptions{
		TelegramID: id, Username: "u" + id, FirstName: "Имя", IsResident: true,
	})
}

// Резидент без выданных прав не должен попасть никуда, кроме портала. Это и
// есть проверка того, что доступ настоящий, а не косметика на главной.
func TestNewResidentReachesNothing(t *testing.T) {
	h, _, kp := newGuardedRouter(t)
	tok := token(t, kp, "42")

	for _, target := range []string{
		"https://inside.akiba.space/jellyfin/",
		"https://inside.akiba.space/sso/jellyfin",
		"https://inside.akiba.space/qbittorrent/",
		"https://inside.akiba.space/nextcloud",
		"https://inside.akiba.space/admin",
	} {
		w := request(t, h, target, tok)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: код %d, ожидался 403", target, w.Code)
		}
	}
}

// Портал такому резиденту не показывает ни одной карточки: список карточек и
// право зайти по адресу берутся из одного источника.
func TestPortalShowsNoCardsWithoutGrants(t *testing.T) {
	h, _, kp := newGuardedRouter(t)
	w := request(t, h, "https://inside.akiba.space/", token(t, kp, "42"))

	body := w.Body.String()
	for _, card := range []string{"/jellyfin", "/qbittorrent/", "/nextcloud", "/admin"} {
		if strings.Contains(body, `href="`+card+`"`) {
			t.Errorf("на портале есть карточка %q без выданных прав", card)
		}
	}
}

// Выдали доступ — сервис открылся. Проверяем именно через роутер: между
// галочкой и реальным доступом лежат Guard, политика и Require.
func TestGrantOpensService(t *testing.T) {
	h, grants, kp := newGuardedRouter(t)
	tok := token(t, kp, "42")

	if w := request(t, h, "https://inside.akiba.space/jellyfin/", tok); w.Code != http.StatusForbidden {
		t.Fatalf("до выдачи код %d, ожидался 403", w.Code)
	}

	grants.set("42", "jellyfin")

	w := request(t, h, "https://inside.akiba.space/jellyfin/", tok)
	if w.Code != http.StatusOK || w.Body.String() != "jellyfin-proxy" {
		t.Fatalf("после выдачи код %d, тело %q", w.Code, w.Body.String())
	}
}

// И обратное: администратор снял галочку — доступ закрылся немедленно, без
// перезапуска шлюза и без ожидания истечения куки.
func TestRevokeClosesServiceImmediately(t *testing.T) {
	h, grants, kp := newGuardedRouter(t)
	tok := token(t, kp, "42")
	grants.set("42", "jellyfin", "qbittorrent")

	if w := request(t, h, "https://inside.akiba.space/qbittorrent/", tok); w.Code != http.StatusOK {
		t.Fatalf("до отзыва код %d, ожидался 200", w.Code)
	}

	grants.set("42", "jellyfin") // администратор снял галочку qBittorrent

	w := request(t, h, "https://inside.akiba.space/qbittorrent/", tok)
	if w.Code != http.StatusForbidden {
		t.Fatalf("после отзыва код %d, ожидался 403", w.Code)
	}
	// Соседний сервис при этом остаётся доступным.
	if w := request(t, h, "https://inside.akiba.space/jellyfin/", tok); w.Code != http.StatusOK {
		t.Fatalf("отозвали лишнее: jellyfin отвечает %d", w.Code)
	}
}

// Отзыв прав на сам Jellyfin должен закрывать и его внутренние адреса, а не
// только вход: веб-интерфейс ходит по ним десятками запросов.
func TestRevokeClosesNestedPaths(t *testing.T) {
	h, grants, kp := newGuardedRouter(t)
	tok := token(t, kp, "42")
	grants.set("42", "jellyfin")

	deep := "https://inside.akiba.space/jellyfin/web/index.html"
	if w := request(t, h, deep, tok); w.Code != http.StatusOK {
		t.Fatalf("до отзыва код %d", w.Code)
	}

	grants.set("42")

	if w := request(t, h, deep, tok); w.Code != http.StatusForbidden {
		t.Fatalf("внутренний адрес остался доступен: код %d", w.Code)
	}
}

// Права одного резидента не должны открывать сервис другому.
func TestGrantsAreNotShared(t *testing.T) {
	h, grants, kp := newGuardedRouter(t)
	grants.set("42", "jellyfin")

	w := request(t, h, "https://inside.akiba.space/jellyfin/", token(t, kp, "43"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("чужие права открыли доступ: код %d", w.Code)
	}
}

// Админка — такой же сервис: без права на неё резидент не откроет её и не
// сможет ничего себе выдать.
func TestAdminIsClosedWithoutGrant(t *testing.T) {
	h, grants, kp := newGuardedRouter(t)
	tok := token(t, kp, "42")
	grants.set("42", "jellyfin", "qbittorrent", "nextcloud")

	if w := request(t, h, "https://inside.akiba.space/admin", tok); w.Code != http.StatusForbidden {
		t.Fatalf("админка открыта без права: код %d", w.Code)
	}

	// POST тоже: иначе форму можно было бы отправить мимо страницы.
	r := httptest.NewRequest(http.MethodPost, "https://inside.akiba.space/admin",
		strings.NewReader("user=1&service=jellyfin"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: "token", Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("форма админки принята без права: код %d", w.Code)
	}
}

// Второй администратор назначается выдачей права admin — ради этого сервис и
// показывается в галочках наравне с остальными.
func TestGrantedAdminOpensPanel(t *testing.T) {
	h, grants, kp := newGuardedRouter(t)
	grants.set("42", string(access.Admin))

	w := request(t, h, "https://inside.akiba.space/admin", token(t, kp, "42"))
	if w.Code != http.StatusOK || w.Body.String() != "admin" {
		t.Fatalf("код %d, тело %q", w.Code, w.Body.String())
	}
}

// Администратору из конфигурации доступно всё, даже когда в базе на него нет
// ни одной строки: иначе одна неверная галочка заперла бы систему.
func TestRootAdminReachesEverything(t *testing.T) {
	h, _, kp := newGuardedRouter(t)
	tok := token(t, kp, rootAdminID)

	for _, target := range []string{
		"https://inside.akiba.space/jellyfin/",
		"https://inside.akiba.space/qbittorrent/",
		"https://inside.akiba.space/nextcloud",
		"https://inside.akiba.space/admin",
	} {
		if w := request(t, h, target, tok); w.Code != http.StatusOK {
			t.Errorf("%s: код %d, ожидался 200", target, w.Code)
		}
	}
}

// Аноним не проходит даже первый рубеж: его отправляют на вход, а не
// показывают отказ по правам.
func TestAnonymousIsSentToLogin(t *testing.T) {
	h, grants, _ := newGuardedRouter(t)
	grants.set("42", "jellyfin")

	w := request(t, h, "https://inside.akiba.space/jellyfin/", "")
	if w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался редирект на вход", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "auth.akiba.space") {
		t.Fatalf("Location = %q", w.Header().Get("Location"))
	}
}
