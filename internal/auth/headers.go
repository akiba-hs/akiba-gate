package auth

import "net/http"

// Заголовки, которыми шлюз сообщает бэкендам, кто именно пришёл.
//
// Их выставляет только ForwardAuth-ответ. Любые такие заголовки, пришедшие
// от клиента, обязаны вычищаться — иначе представиться чужим резидентом
// можно одним curl.
const (
	HeaderUID        = "X-Akiba-Uid"
	HeaderUser       = "X-Akiba-User"
	HeaderName       = "X-Akiba-Name"
	HeaderTelegramID = "X-Akiba-Telegram-Id"
	HeaderResident   = "X-Akiba-Resident"
)

// identityHeaders — полный список заголовков идентичности.
var identityHeaders = []string{
	HeaderUID, HeaderUser, HeaderName, HeaderTelegramID, HeaderResident,
}

// StripIdentityHeaders удаляет заголовки идентичности из входящего запроса.
//
// Вызывается на границе: и в ForwardAuth, и в каждом прокси. Это вторая линия
// обороны на случай, если middleware в Traefik забыли или неправильно
// сконфигурировали.
func StripIdentityHeaders(h http.Header) {
	for _, name := range identityHeaders {
		h.Del(name)
	}
}

// SetIdentityHeaders проставляет заголовки идентичности по данным токена.
func SetIdentityHeaders(h http.Header, c *Claims) {
	h.Set(HeaderUID, c.UID())
	h.Set(HeaderUser, c.Username)
	h.Set(HeaderName, c.DisplayName())
	h.Set(HeaderTelegramID, c.TelegramID)
	if c.IsResident {
		h.Set(HeaderResident, "true")
	} else {
		h.Set(HeaderResident, "false")
	}
}

// OwnPageHeaders закрывает от фрейминга страницу, которую рисует сам шлюз.
//
// Глобально это ставить нельзя: через шлюз проксируются интерфейсы Jellyfin и
// qBittorrent, и запрет фреймов ломает их. Но собственные страницы — портал с
// формой выхода и страницы входа в сервисы — обрамляться
// чужим сайтом не должны.
func OwnPageHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "frame-ancestors 'self'")
}
