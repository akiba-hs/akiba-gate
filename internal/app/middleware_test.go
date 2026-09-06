package app_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/app"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/portal"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

// httputil.ReverseProxy паникует http.ErrAbortHandler каждый раз, когда
// клиент закрывает вкладку посреди ответа. Перехватывать её нельзя: журнал
// заполнится фальшивыми паниками, а попытка отдать 500 придётся на уже
// начатый ответ.
func TestRouterDoesNotReportClientDisconnectAsPanic(t *testing.T) {
	var logs strings.Builder
	kp := testsupport.NewKeyPair(t)
	v, err := auth.NewVerifier(kp.PublicPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	log := slog.New(slog.NewTextHandler(&logs, nil))
	fa := &auth.ForwardAuth{
		Verifier: v, CookieName: "token",
		AuthURL:       mustURL(t, "https://auth.akiba.space"),
		PublicBaseURL: mustURL(t, "https://inside.akiba.space"),
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
		JellyfinSSO: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(http.ErrAbortHandler)
		}),
		QbitProxy: marker("qbit"), QbitBasePath: "/qbittorrent",
	})

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/sso/jellyfin", nil)
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: "token", Value: kp.ResidentToken(t)})

	defer func() {
		v := recover()
		if v != http.ErrAbortHandler {
			t.Fatalf("ErrAbortHandler должна пролетать наружу, получено %v", v)
		}
		if strings.Contains(logs.String(), "паника в обработчике") {
			t.Fatal("уход клиента записан в журнал как паника")
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), r)
	t.Fatal("паника не была переброшена")
}

func TestAccessLogRecordsStatus(t *testing.T) {
	var logs strings.Builder
	h, _ := newRouterWithLog(t, slog.New(slog.NewTextHandler(&logs, nil)))

	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/healthz", nil))

	out := logs.String()
	if !strings.Contains(out, "status=200") || !strings.Contains(out, "/healthz") {
		t.Fatalf("журнал доступа неполный: %s", out)
	}
}
