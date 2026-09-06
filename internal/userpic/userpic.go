// Пакет userpic отдаёт аватарки Telegram через шлюз.
//
// Зачем прослойка, если картинка и так публичная. Причин две. Первая —
// доступность: t.me у части резидентов не открывается, и портал получал
// битую картинку вместо лица. Вторая — приватность: с прямым адресом каждый
// открытый портал сообщает Telegram, кто и когда его открыл, вместе с
// Referer. Через шлюз наружу ходит только сам шлюз, при необходимости через
// SOCKS5.
//
// Включается прослойка вместе с прокси: при пустом SOCKS5_PROXY портал
// ставит в <img> прямую ссылку на t.me, потому что тот же самый запрос
// браузер сделает быстрее и не через шлюз, а Referer снимается атрибутом
// referrerpolicy. Маршрут при этом остаётся зарегистрированным и остаётся
// за Guard: страницы из кэша могут ссылаться на него ещё сутки.
package userpic

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// Path — префикс, под которым шлюз отдаёт аватарки.
const Path = "/userpic/"

// upstream — адрес, по которому Telegram отдаёт аватарки.
const upstream = "https://t.me/i/userpic/"

// maxSize ограничивает размер картинки. Аватарка Telegram — это десятки
// килобайт; всё, что сильно больше, означает, что мы качаем не то.
const maxSize = 4 << 20

// Handler проксирует картинку из Telegram.
type Handler struct {
	// HTTP — клиент, которым ходим в Telegram. Через него настраивается
	// SOCKS5, если прямой доступ закрыт.
	HTTP *http.Client
	Log  *slog.Logger
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, Path)
	if !validPath(rest) {
		http.Error(w, "некорректный адрес аватарки", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream+rest, nil)
	if err != nil {
		h.Log.Error("не удалось собрать запрос за аватаркой", "error", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	// Ни куки шлюза, ни Referer наружу не уходят: запрос собирается с нуля,
	// а не пересылается.
	req.Header.Set("Accept", "image/*")

	resp, err := h.HTTP.Do(req)
	if err != nil {
		h.Log.Warn("не удалось получить аватарку из Telegram", "error", err)
		http.Error(w, "аватарка недоступна", http.StatusBadGateway)
		return
	}
	// Тело дочитываем только в разумных пределах: соединение из пула ради
	// переиспользования стоит освободить, но качать ради этого хвост
	// негабаритного ответа — нет.
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxSize))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "аватарка недоступна", http.StatusBadGateway)
		return
	}
	// Тип содержимого берём не на веру: без этой проверки чужой ответ мог бы
	// приехать резиденту как HTML с нашего origin.
	ctype := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ctype, "image/") {
		h.Log.Warn("Telegram вернул не картинку", "content_type", ctype)
		http.Error(w, "аватарка недоступна", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Аватарка меняется редко, а адрес содержит её отпечаток, поэтому кэш
	// длинный и приватный: картинка персональная.
	w.Header().Set("Cache-Control", "private, max-age=86400")
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxSize)); err != nil {
		h.Log.Debug("передача аватарки прервана", "error", err)
	}
}

// validPath проверяет хвост адреса.
//
// Пропускаем ровно тот вид, который выдаёт Telegram: «<размер>/<файл>.jpg».
// Никаких «..», слэшей внутри сегментов и произвольных путей — иначе шлюз
// превращается в прокси ко всему t.me.
func validPath(rest string) bool {
	if rest == "" || len(rest) > 256 {
		return false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return false
	}
	size, file := parts[0], parts[1]
	if !isDigits(size) || len(size) > 4 {
		return false
	}
	if !strings.HasSuffix(file, ".jpg") || len(file) < 5 {
		return false
	}
	for _, c := range file[:len(file)-4] {
		if !isFileRune(c) {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isFileRune разрешает алфавит, в котором Telegram называет файлы аватарок.
func isFileRune(c rune) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '_':
		return true
	}
	return false
}

// Rewrite превращает прямой адрес аватарки Telegram в адрес шлюза.
// Чужие адреса не трогает: подставлять их в src нельзя, а молча ломать —
// хуже, чем показать как есть.
func Rewrite(raw string) string {
	if !strings.HasPrefix(raw, upstream) {
		return raw
	}
	rest := strings.TrimPrefix(raw, upstream)
	if !validPath(rest) {
		return ""
	}
	return Path + rest
}
