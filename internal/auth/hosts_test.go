package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/auth"
)

func policy(t *testing.T) auth.HostPolicy {
	t.Helper()
	return auth.HostPolicy{
		Base:    mustURL(t, "https://inside.akiba.space"),
		Allowed: []string{"nextcloud.akiba.space"},
	}
}

func TestHostPolicyAllows(t *testing.T) {
	p := policy(t)
	for host, want := range map[string]bool{
		"inside.akiba.space":    true,
		"nextcloud.akiba.space": true,
		"evil.example":          false,
		"":                      false,
		"auth.akiba.space":      false,
		"inside.akiba.space.":   false,
	} {
		if got := p.Allows(host); got != want {
			t.Fatalf("Allows(%q) = %v, ожидалось %v", host, got, want)
		}
	}
}

// Схему сохраняем: из локальной сети шлюз открывают по http, и подмена на
// https увела бы страницу на другой origin.
func TestHostPolicyOriginKeepsScheme(t *testing.T) {
	p := policy(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	r.Header.Set("X-Forwarded-Proto", "http")

	origin, ok := p.Origin(r)
	if !ok || origin != "http://inside.akiba.space" {
		t.Fatalf("origin = %q, ok = %v", origin, ok)
	}
}

func TestHostPolicyOriginFallsBackForForeignHost(t *testing.T) {
	p := policy(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "evil.example"

	origin, ok := p.Origin(r)
	if ok {
		t.Fatal("посторонний хост признан своим")
	}
	if origin != "https://inside.akiba.space" {
		t.Fatalf("origin = %q, ожидался откат на канонический адрес", origin)
	}
}

func TestRequestHostPrefersForwardedHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "internal:8080"
	if got := auth.RequestHost(r); got != "internal:8080" {
		t.Fatalf("RequestHost = %q", got)
	}
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	if got := auth.RequestHost(r); got != "inside.akiba.space" {
		t.Fatalf("RequestHost = %q", got)
	}
}

// Схема приходит заголовком, а склеенный из неё origin уходит и в
// redirect_uri, и в localStorage браузера, и в проверку Origin для
// qBittorrent. Ничего, кроме http и https, туда попасть не должно.
func TestRequestSchemeRejectsUnknownScheme(t *testing.T) {
	for _, proto := range []string{"javascript", "ftp", "HTTPS ", "data"} {
		r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/", nil)
		r.Header.Set("X-Forwarded-Proto", proto)
		if got := auth.RequestScheme(r); got != "http" {
			t.Errorf("X-Forwarded-Proto %q дал схему %q, ожидался откат на http", proto, got)
		}
	}
	for _, proto := range []string{"http", "https"} {
		r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/", nil)
		r.Header.Set("X-Forwarded-Proto", proto)
		if got := auth.RequestScheme(r); got != proto {
			t.Errorf("схема %q не сохранена, получено %q", proto, got)
		}
	}
}
