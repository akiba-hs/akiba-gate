// Package upstream — общие детали обращения к сервисам за шлюзом.
//
// Шлюз проксирует несколько сервисов (Jellyfin, qBittorrent), и у каждого свой
// пакет. Но две вещи устроены у всех одинаково: сборка адреса запроса к сервису
// и приведение Location из его ответа к адресу шлюза. Разъехавшись, копии этого
// кода дали бы разное поведение на одинаковом вводе — причём заметное не сразу,
// а на редком редиректе. Поэтому они живут здесь в одном экземпляре.
package upstream

import (
	"net/url"
	"strings"
)

// RequestURL собирает адрес запроса к сервису: базовый адрес плюс путь.
//
// Строку запроса отделяем явно: иначе "?" уедет в путь и будет заэкранирован
// как %3F, а сервис получит адрес, которого не знает.
func RequestURL(base *url.URL, path string) url.URL {
	u := *base
	if i := strings.IndexByte(path, '?'); i >= 0 {
		u.Path, u.RawQuery = base.Path+path[:i], path[i+1:]
	} else {
		u.Path = base.Path + path
	}
	return u
}

// Relocate приводит Location из ответа сервиса к адресу шлюза.
//
// Сервис о префиксе не знает и отвечает, например, «Location: /web/» на
// запрос корня. Хуже другой случай: с настроенной поддержкой обратного
// прокси сервис отдаёт абсолютный адрес со своим внутренним хостом
// («http://192.168.8.43:8096/web/»). Резидент из интернета такого хоста не
// увидит вовсе, а сам адрес выдаёт устройство локальной сети — поэтому
// внутренний хост заменяем на префикс шлюза.
func Relocate(loc, basePath, upstreamHost string) string {
	if loc == "" || basePath == "" {
		return loc
	}
	if strings.HasPrefix(loc, "/") {
		if strings.HasPrefix(loc, basePath+"/") || loc == basePath {
			return loc
		}
		return basePath + loc
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" || u.Host != upstreamHost {
		// Чужой хост не трогаем: это редирект наружу, и подменять его нельзя.
		return loc
	}
	u.Scheme, u.Host = "", ""
	rest := u.String()
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	if strings.HasPrefix(rest, basePath+"/") || rest == basePath {
		return rest
	}
	return basePath + rest
}
