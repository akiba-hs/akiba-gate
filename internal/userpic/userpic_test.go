package userpic_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/userpic"
)

const sample = "U1U6xmdeEGqQkK-v9p-6-8-_pTsk7oM_N2-DuNPgPKA.jpg"

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// telegramStub изображает t.me и запоминает запрошенный путь.
type telegramStub struct {
	path        string
	status      int
	contentType string
	body        string
	cookie      string
}

// client подменяет транспорт так, что любой запрос уходит в заглушку.
func (s *telegramStub) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		s.path = r.URL.Path
		s.cookie = r.Header.Get("Cookie")
		return &http.Response{
			StatusCode: s.status,
			Header:     http.Header{"Content-Type": {s.contentType}},
			Body:       io.NopCloser(strings.NewReader(s.body)),
			Request:    r,
		}, nil
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func get(t *testing.T, s *telegramStub, path string) *httptest.ResponseRecorder {
	t.Helper()
	h := userpic.Handler{HTTP: s.client(), Log: quiet()}
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: "jwt-rezidenta"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandlerProxiesImage(t *testing.T) {
	s := &telegramStub{status: http.StatusOK, contentType: "image/jpeg", body: "картинка"}
	w := get(t, s, userpic.Path+"320/"+sample)

	if w.Code != http.StatusOK {
		t.Fatalf("код %d", w.Code)
	}
	if w.Body.String() != "картинка" {
		t.Errorf("тело %q", w.Body.String())
	}
	if s.path != "/i/userpic/320/"+sample {
		t.Errorf("в Telegram ушёл путь %q", s.path)
	}
	if w.Header().Get("Content-Type") != "image/jpeg" {
		t.Errorf("Content-Type = %q", w.Header().Get("Content-Type"))
	}
}

// Кука шлюза наружу уходить не должна: запрос собирается с нуля.
func TestHandlerDoesNotForwardCookies(t *testing.T) {
	s := &telegramStub{status: http.StatusOK, contentType: "image/jpeg", body: "x"}
	get(t, s, userpic.Path+"320/"+sample)

	if s.cookie != "" {
		t.Fatalf("в Telegram ушла кука %q", s.cookie)
	}
}

// Иначе шлюз становится прокси ко всему t.me и открытым каналом для чужого
// содержимого с нашего origin.
func TestHandlerRejectsForeignPaths(t *testing.T) {
	s := &telegramStub{status: http.StatusOK, contentType: "image/jpeg", body: "x"}
	for _, path := range []string{
		userpic.Path + "320/../../secret.jpg",
		userpic.Path + "320/файл.jpg",
		userpic.Path + "abc/" + sample,
		userpic.Path + "320/" + sample + "/more",
		userpic.Path + "320/script.js",
		userpic.Path,
	} {
		if w := get(t, s, path); w.Code != http.StatusBadRequest {
			t.Errorf("путь %q принят с кодом %d", path, w.Code)
		}
	}
}

// Не картинка от Telegram — это ошибка, а не содержимое для резидента.
func TestHandlerRejectsNonImage(t *testing.T) {
	s := &telegramStub{status: http.StatusOK, contentType: "text/html", body: "<script>"}
	w := get(t, s, userpic.Path+"320/"+sample)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("код %d, ожидался 502", w.Code)
	}
	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("чужой HTML отдан с нашего origin")
	}
}

func TestRewriteReplacesTelegramURL(t *testing.T) {
	got := userpic.Rewrite("https://t.me/i/userpic/320/" + sample)
	if got != userpic.Path+"320/"+sample {
		t.Fatalf("получено %q", got)
	}
}

// Чужой адрес не наш: подставлять его в наш префикс нельзя.
func TestRewriteLeavesForeignURLAlone(t *testing.T) {
	const foreign = "https://evil.example/pic.jpg"
	if got := userpic.Rewrite(foreign); got != foreign {
		t.Fatalf("чужой адрес изменён на %q", got)
	}
}

// Адрес с виду от Telegram, но с недопустимым хвостом — не показываем вовсе.
func TestRewriteDropsMalformedTelegramURL(t *testing.T) {
	if got := userpic.Rewrite("https://t.me/i/userpic/320/../../etc/passwd"); got != "" {
		t.Fatalf("получено %q, ожидалась пустая строка", got)
	}
}
