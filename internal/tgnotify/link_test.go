package tgnotify_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
)

func openLink(t *testing.T, query string) *httptest.ResponseRecorder {
	t.Helper()
	h := tgnotify.LinkHandler{Log: quiet()}
	r := httptest.NewRequest(http.MethodGet, tgnotify.TorrentLinkPath+query, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLinkRedirectsToMagnet(t *testing.T) {
	magnet := "magnet:?xt=urn:btih:" + strings.Repeat("a", 40) + "&dn=Ubuntu"
	w := openLink(t, "?l="+base64.RawURLEncoding.EncodeToString([]byte(magnet)))

	if w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != magnet {
		t.Fatalf("Location = %q, ожидался магнит", got)
	}
}

// Клиенты по-разному обходятся с выравниванием base64, и ссылка должна
// открываться в обоих видах.
func TestLinkAcceptsPaddedBase64(t *testing.T) {
	magnet := "magnet:?xt=urn:btih:abc"
	w := openLink(t, "?l="+base64.URLEncoding.EncodeToString([]byte(magnet)))

	if w.Code != http.StatusFound {
		t.Fatalf("код %d, ожидался 302", w.Code)
	}
}

// Без проверки схемы адрес превратился бы в открытый редиректор, которым
// удобно прикрывать фишинг настоящим доменом.
func TestLinkRejectsForeignScheme(t *testing.T) {
	for _, target := range []string{"https://evil.example", "javascript:alert(1)", "//evil.example"} {
		w := openLink(t, "?l="+base64.RawURLEncoding.EncodeToString([]byte(target)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("адрес %q принят с кодом %d", target, w.Code)
		}
	}
}

func TestLinkRejectsGarbage(t *testing.T) {
	for _, q := range []string{"", "?l=", "?l=не-base64!!!"} {
		if w := openLink(t, q); w.Code != http.StatusBadRequest {
			t.Errorf("запрос %q принят с кодом %d", q, w.Code)
		}
	}
}
