// Пакет tgnotify сообщает в групповой чат Telegram о добавленных торрентах.
//
// Устройство намеренно простое: один запрос sendMessage к Bot API через
// обычный net/http, без клиентских библиотек. Всё, что нужно, — токен бота и
// идентификатор чата; и то и другое живёт в конфигурации, а не в коде.
//
// Ключевое свойство — необязательность. Если токена или чата нет, сервис
// обязан работать как прежде: Notifier создаётся выключенным, вызовы у него
// ничего не делают, а один раз при старте в журнал уходит внятное объяснение,
// почему уведомлений не будет. Так включение бота не превращается в условие
// запуска шлюза.
package tgnotify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TorrentLinkPath — адрес перехода на магнит-ссылку.
//
// В сообщение уходит ссылка на шлюз, а не магнит напрямую: Telegram не делает
// кликабельными схемы вроде magnet:, и ссылка выглядела бы голым текстом.
const TorrentLinkPath = "/trrntlink"

// Event — то, о чём сообщаем.
type Event struct {
	// Username — ник в Telegram без «собаки». Может быть пустым: не у всех
	// он выставлен, тогда показываем отображаемое имя.
	Username string
	// DisplayName — запасное имя, если ника нет.
	DisplayName string
	// TorrentName — название торрента, оно же текст ссылки.
	TorrentName string
	// Magnet — магнит-ссылка. Может быть пустой: для .torrent, добавленного
	// файлом, она собирается из infohash, а для ссылки на файл её нет вовсе.
	Magnet string
}

// Messages отдаёт шаблон сообщения. Интерфейс, а не строка, потому что текст
// обязан читаться свежим на каждую отправку: правка файла переводов должна
// менять сообщения без перезапуска.
type Messages interface {
	// TorrentAdded возвращает шаблон с плейсхолдерами {user} и {torrent}.
	TorrentAdded() string
	// TorrentDownloaded возвращает шаблон личного сообщения о законченной
	// загрузке. Плейсхолдер один — {torrent}: адресат и так знает, что
	// это он добавил торрент.
	TorrentDownloaded() string
}

// Notifier отправляет сообщения в чат. Выключенный Notifier молчит.
type Notifier struct {
	token   string
	chatID  string
	baseURL string // публичный адрес шлюза, из него строится ссылка на магнит
	api     string // адрес Bot API, подменяется в тестах
	http    *http.Client
	msgs    Messages
	log     *slog.Logger
}

// Config — всё, что нужно для отправки.
type Config struct {
	Token   string
	ChatID  string
	BaseURL string
	// HTTP задаёт клиента: через него настраивается выход в Telegram через
	// SOCKS5, если прямой доступ закрыт.
	HTTP *http.Client
	// APIBase позволяет подменить адрес Bot API в тестах.
	APIBase string
}

// New создаёт уведомитель. Отсутствие токена или чата — не ошибка: вернётся
// выключенный экземпляр, а причина уйдёт в журнал ровно один раз, при старте.
func New(cfg Config, msgs Messages, log *slog.Logger) *Notifier {
	n := &Notifier{
		token: cfg.Token, chatID: cfg.ChatID, baseURL: strings.TrimSuffix(cfg.BaseURL, "/"),
		api: cfg.APIBase, http: cfg.HTTP, msgs: msgs, log: log,
	}
	if n.api == "" {
		n.api = "https://api.telegram.org"
	}
	if n.http == nil {
		n.http = &http.Client{Timeout: 10 * time.Second}
	}
	switch {
	case cfg.Token == "" && cfg.ChatID == "":
		log.Info("в конфигурации нет TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID: " +
			"бот не будет сообщать о новых торрентах")
	case cfg.Token == "":
		log.Info("в конфигурации нет TELEGRAM_BOT_TOKEN: " +
			"бот не будет сообщать о новых торрентах")
	case cfg.ChatID == "":
		log.Info("в конфигурации нет TELEGRAM_CHAT_ID: " +
			"бот не будет сообщать о новых торрентах")
	default:
		log.Info("бот будет сообщать о новых торрентах", "chat", cfg.ChatID)
	}
	return n
}

// HTTPClient возвращает клиента, которым уведомитель ходит в Telegram.
//
// Нужен снаружи ровно для одного: проверить, что бот и аватарки ходят через
// один и тот же клиент, то есть через один и тот же SOCKS5. Инвариант живёт
// в сборке зависимостей, а без доступа сюда его нельзя было бы подтвердить
// ничем, кроме внимательного чтения main.
func (n *Notifier) HTTPClient() *http.Client { return n.http }

// Enabled сообщает, может ли бот писать в групповой чат.
func (n *Notifier) Enabled() bool { return n.token != "" && n.chatID != "" }

// DirectEnabled сообщает, может ли бот писать в личку.
//
// Чат для этого не нужен, достаточно токена: адресатом выступает сам
// резидент, и его идентификатор приходит из токена авторизации. Поэтому
// личные сообщения работают и там, где TELEGRAM_CHAT_ID не задан.
func (n *Notifier) DirectEnabled() bool { return n.token != "" }

// Notify отправляет сообщение о добавленном торренте.
//
// Вызывать его для торрента без известного автора не нужно и не следует:
// смысл сообщения — «кто именно добавил», и без имени оно бессмысленно.
func (n *Notifier) Notify(ctx context.Context, e Event) error {
	if !n.Enabled() {
		return nil
	}
	// Сообщение служебное и приходит на каждый добавленный торрент,
	// поэтому оно максимально тихое: без звука и уведомления у всех
	// участников чата.
	return n.send(ctx, n.chatID, n.render(e), true)
}

// NotifyDownloaded пишет в личку тому, кто добавил торрент, что загрузка
// закончилась.
//
// В отличие от сообщения в чат — со звуком: это ответ на действие конкретного
// человека, и он его ждёт. Групповой чат от этого не страдает, потому что
// адресат здесь один.
//
// Ошибку возвращаем, но лечить её нечем: самый частый отказ — «bot can't
// initiate conversation with a user», то есть человек ни разу не написал
// боту. Требовать этого от резидента ради необязательного уведомления
// незачем, поэтому вызывающий код только пишет в журнал.
func (n *Notifier) NotifyDownloaded(ctx context.Context, telegramID, torrentName string) error {
	if !n.DirectEnabled() {
		return nil
	}
	if telegramID == "" {
		return fmt.Errorf("tgnotify: не указан адресат личного сообщения")
	}
	name := html.EscapeString(torrentName)
	if name == "" {
		name = "торрент"
	}
	text := strings.ReplaceAll(n.msgs.TorrentDownloaded(), "{torrent}", name)
	return n.send(ctx, telegramID, text, false)
}

// send отправляет одно сообщение. silent=true убирает звук и уведомление.
func (n *Notifier) send(ctx context.Context, chatID, text string, silent bool) error {
	form := url.Values{
		"chat_id":    {chatID},
		"text":       {text},
		"parse_mode": {"HTML"},
		// Превью не разворачиваем никогда: ссылка в сообщении ведёт на шлюз,
		// и её карточка не добавила бы ничего, кроме шума.
		"disable_notification":     {strconv.FormatBool(silent)},
		"disable_web_page_preview": {"true"},
	}
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", n.api, n.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("tgnotify: сборка запроса: %s", n.redact(err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.http.Do(req)
	if err != nil {
		return fmt.Errorf("tgnotify: отправка сообщения: %s", n.redact(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tgnotify: Telegram ответил %d: %s",
			resp.StatusCode, n.redactString(strings.TrimSpace(string(body))))
	}
	var res struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &res); err == nil && !res.OK {
		return fmt.Errorf("tgnotify: Telegram отклонил сообщение: %s", res.Description)
	}
	return nil
}

// redact убирает из ошибки токен бота.
//
// Токен стоит прямо в пути Bot API, а http.Client оборачивает любую сетевую
// ошибку в *url.Error, который печатает адрес целиком. Ошибка при этом уходит
// в журнал — то есть при каждой недоступности Telegram (а ради неё и заведён
// SOCKS5) токен оказывался бы в логе, который читают куда шире, чем чат.
func (n *Notifier) redact(err error) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		// Копия: исходную ошибку портить нельзя, её мог сохранить вызывающий.
		clean := *ue
		clean.URL = n.api + "/bot…/sendMessage"
		return n.redactString(clean.Error())
	}
	return n.redactString(err.Error())
}

// redactString — вторая линия: замена по самому токену на случай, если он
// приедет не через url.Error.
func (n *Notifier) redactString(s string) string {
	if n.token == "" {
		return s
	}
	return strings.ReplaceAll(s, n.token, "…")
}

// render собирает текст сообщения по шаблону из файла переводов.
func (n *Notifier) render(e Event) string {
	user := e.Username
	if user != "" {
		user = "@" + user
	} else if user = e.DisplayName; user == "" {
		user = "неизвестный"
	}

	torrent := html.EscapeString(e.TorrentName)
	if torrent == "" {
		torrent = "торрент"
	}
	if link := n.TorrentLink(e.Magnet); link != "" {
		torrent = fmt.Sprintf(`<a href="%s">%s</a>`, html.EscapeString(link), torrent)
	}

	tmpl := n.msgs.TorrentAdded()
	tmpl = strings.ReplaceAll(tmpl, "{user}", html.EscapeString(user))
	return strings.ReplaceAll(tmpl, "{torrent}", torrent)
}

// TorrentLink строит адрес перехода на магнит через шлюз.
// Для пустого магнита возвращает пустую строку — ссылки просто не будет.
func (n *Notifier) TorrentLink(magnet string) string {
	if magnet == "" || n.baseURL == "" {
		return ""
	}
	return n.baseURL + TorrentLinkPath + "?l=" + base64.RawURLEncoding.EncodeToString([]byte(magnet))
}

// Membership — состоит ли человек в групповом чате.
type Membership int

const (
	// MembershipUnknown — выяснить не удалось. Отличать обязательно: принять
	// сбой сети за «человека нет в чате» значило бы вычистить из базы всех
	// резидентов на время недоступности Telegram.
	MembershipUnknown Membership = iota
	// MembershipIn — состоит (создатель, администратор, участник или
	// участник с ограничениями).
	MembershipIn
	// MembershipOut — вышел или исключён.
	MembershipOut
)

// ChatMemberProfile — имя и ник участника по данным Telegram.
type ChatMemberProfile struct {
	Username  string
	FirstName string
	LastName  string
}

// ChatMember узнаёт, состоит ли человек в групповом чате бота, и заодно
// отдаёт его свежие имя и ник.
//
// Нужен админке. Список резидентов в базе наполняется входами и сам по себе
// не уменьшается, а членство в чате — единственный признак, по которому
// человека оттуда можно убрать. Имя и ник приходят тем же запросом: человек
// мог смениться, пока не заходил на портал, и второй вызов ради этого был бы
// лишним обращением к Telegram на каждого резидента.
func (n *Notifier) ChatMember(ctx context.Context, telegramID string) (Membership, ChatMemberProfile, error) {
	if !n.Enabled() {
		return MembershipUnknown, ChatMemberProfile{}, nil
	}
	form := url.Values{"chat_id": {n.chatID}, "user_id": {telegramID}}
	endpoint := fmt.Sprintf("%s/bot%s/getChatMember", n.api, n.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return MembershipUnknown, ChatMemberProfile{}, fmt.Errorf("tgnotify: сборка запроса: %s", n.redact(err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.http.Do(req)
	if err != nil {
		return MembershipUnknown, ChatMemberProfile{},
			fmt.Errorf("tgnotify: запрос состава чата: %s", n.redact(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

	var res struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      struct {
			Status   string `json:"status"`
			IsMember bool   `json:"is_member"`
			User     struct {
				Username  string `json:"username"`
				FirstName string `json:"first_name"`
				LastName  string `json:"last_name"`
			} `json:"user"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return MembershipUnknown, ChatMemberProfile{},
			fmt.Errorf("tgnotify: разбор ответа о составе чата: %s",
				n.redactString(strings.TrimSpace(string(body))))
	}
	profile := ChatMemberProfile{
		Username:  res.Result.User.Username,
		FirstName: res.Result.User.FirstName,
		LastName:  res.Result.User.LastName,
	}
	if !res.OK {
		if strings.Contains(strings.ToLower(res.Description), "user not found") {
			return MembershipOut, profile, nil
		}
		return MembershipUnknown, profile,
			fmt.Errorf("tgnotify: Telegram отклонил запрос о составе чата: %s",
				n.redactString(res.Description))
	}
	switch res.Result.Status {
	case "creator", "administrator", "member":
		return MembershipIn, profile, nil
	case "restricted":
		if res.Result.IsMember {
			return MembershipIn, profile, nil
		}
		return MembershipOut, profile, nil
	case "left", "kicked":
		return MembershipOut, profile, nil
	default:
		return MembershipUnknown, profile,
			fmt.Errorf("tgnotify: неизвестный статус участника %q", res.Result.Status)
	}
}
