package upstream_test

import (
	"net/url"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/upstream"
)

func TestRequestURLSeparatesQuery(t *testing.T) {
	base, err := url.Parse("http://127.0.0.1:8096/svc")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	cases := []struct {
		name string
		path string
		want string
	}{
		{"без строки запроса", "/System/Info", "http://127.0.0.1:8096/svc/System/Info"},
		// Ради этого случая функция и написана: "?" в пути был бы заэкранирован
		// как %3F, и сервис получил бы адрес, которого не знает.
		{"со строкой запроса", "/api/v2/torrents/info?filter=all", "http://127.0.0.1:8096/svc/api/v2/torrents/info?filter=all"},
		{"пустой путь", "", "http://127.0.0.1:8096/svc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := upstream.RequestURL(base, tc.path)
			if got := u.String(); got != tc.want {
				t.Fatalf("RequestURL = %q, ожидалось %q", got, tc.want)
			}
			if base.Path != "/svc" || base.RawQuery != "" {
				t.Fatalf("базовый адрес испорчен: %q", base.String())
			}
		})
	}
}

func TestRelocate(t *testing.T) {
	cases := []struct {
		name     string
		loc      string
		basePath string
		host     string
		want     string
	}{
		{"пустой Location", "", "/jellyfin", "svc:8096", ""},
		{"без префикса шлюза", "/web/", "/jellyfin", "svc:8096", "/jellyfin/web/"},
		{"префикс уже на месте", "/jellyfin/web/", "/jellyfin", "svc:8096", "/jellyfin/web/"},
		{"ровно префикс", "/jellyfin", "/jellyfin", "svc:8096", "/jellyfin"},
		{"внутренний хост сервиса", "http://svc:8096/web/", "/jellyfin", "svc:8096", "/jellyfin/web/"},
		// Редирект наружу трогать нельзя: это чужой сайт, а не сервис за шлюзом.
		{"чужой хост", "https://example.org/login", "/jellyfin", "svc:8096", "https://example.org/login"},
		{"префикс не задан", "/web/", "", "svc:8096", "/web/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := upstream.Relocate(tc.loc, tc.basePath, tc.host); got != tc.want {
				t.Fatalf("Relocate = %q, ожидалось %q", got, tc.want)
			}
		})
	}
}
