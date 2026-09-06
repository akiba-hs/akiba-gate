package auth

import (
	"net/http"
	"net/url"
)

// HostPolicy решает, какому имени хоста в запросе можно верить.
//
// Зачем это отдельный тип: имя хоста берётся из X-Forwarded-Host или Host,
// то есть приходит извне. По непроверенному имени собираются адрес возврата
// после входа и адрес сервера, который записывается в localStorage браузера.
// И то, и другое, будучи подменённым, превращается в рабочую фишинговую
// ссылку с настоящим доменом auth.akiba.space в адресной строке. Проверка
// должна быть одна на все места, где такой адрес строится, иначе её забудут
// в одном из них — что и произошло до появления этого типа.
type HostPolicy struct {
	Base    *url.URL // канонический публичный адрес шлюза
	Allowed []string // дополнительные свои хосты (например, домен Nextcloud)
}

// Allows сообщает, является ли хост нашим.
func (p HostPolicy) Allows(host string) bool {
	if host == "" {
		return false
	}
	if p.Base != nil && host == p.Base.Host {
		return true
	}
	for _, h := range p.Allowed {
		if host == h {
			return true
		}
	}
	return false
}

// RequestHost возвращает имя хоста из запроса без проверки.
func RequestHost(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		return h
	}
	return r.Host
}

// RequestScheme определяет схему исходного запроса.
//
// Схему сохраняем как есть: из локальной сети шлюз открывают по http, и
// подменять её на https нельзя — страница на http, обратившаяся к https-адресу
// того же имени, получит уже другой origin со всеми последствиями.
func RequestScheme(r *http.Request) string {
	// Значение приходит из заголовка, а склеенный из него origin уходит и в
	// redirect_uri, и в localStorage браузера, и в проверку Origin для
	// qBittorrent. Схем, кроме двух, там быть не может — всё остальное
	// отбрасываем, а не передаём дальше.
	switch proto := r.Header.Get("X-Forwarded-Proto"); proto {
	case "http", "https":
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// Origin возвращает проверенный "схема://хост" запроса.
// Для постороннего хоста откатывается на канонический адрес шлюза.
func (p HostPolicy) Origin(r *http.Request) (origin string, ok bool) {
	host := RequestHost(r)
	if !p.Allows(host) {
		if p.Base == nil {
			return "", false
		}
		return p.Base.Scheme + "://" + p.Base.Host, false
	}
	return RequestScheme(r) + "://" + host, true
}
