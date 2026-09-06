package tgnotify

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// LinkHandler переводит ссылку из сообщения бота на саму магнит-ссылку.
//
// Зачем прослойка. В сообщение нельзя положить magnet: напрямую — Telegram не
// делает такие адреса кликабельными. Поэтому в чат уходит обычный http-адрес
// шлюза, а магнит едет в нём закодированным.
//
// Маршрут открыт без авторизации намеренно: ссылку читают в групповом чате, и
// требовать там куку шлюза значило бы, что она не работает ни у кого. Ничего
// секретного она не раскрывает — магнит и так виден любому участнику чата,
// потому что закодирован прямо в адресе.
type LinkHandler struct {
	Log *slog.Logger
}

func (h LinkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("l")
	if raw == "" {
		http.Error(w, "не указана ссылка", http.StatusBadRequest)
		return
	}
	magnet, err := decodeMagnet(raw)
	if err != nil {
		h.Log.Warn("некорректная ссылка на торрент", "error", err)
		http.Error(w, "некорректная ссылка", http.StatusBadRequest)
		return
	}

	// Схему проверяем обязательно: без этого адрес превращается в открытый
	// редиректор, которым удобно прикрывать фишинг чужим доменом.
	if !strings.HasPrefix(magnet, "magnet:?") {
		h.Log.Warn("в ссылке на торрент не магнит", "scheme", schemeOf(magnet))
		http.Error(w, "ссылка не является магнит-ссылкой", http.StatusBadRequest)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, magnet, http.StatusFound)
}

// decodeMagnet принимает и base64url без выравнивания, и обычный с ним:
// ссылку могли скопировать вручную или переслать через клиент, который
// добавит «=».
func decodeMagnet(raw string) (string, error) {
	if data, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return string(data), nil
	}
	data, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func schemeOf(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return "неразбираемая"
	}
	if u.Scheme == "" {
		return "отсутствует"
	}
	return u.Scheme
}
