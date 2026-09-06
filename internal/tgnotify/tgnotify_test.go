package tgnotify_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// texts отдаёт шаблон, как это делает файл переводов.
type texts struct{ tmpl, downloaded string }

func (t texts) TorrentAdded() string {
	if t.tmpl == "" {
		return "Резидент {user} добавил {torrent}"
	}
	return t.tmpl
}

func (t texts) TorrentDownloaded() string {
	if t.downloaded != "" {
		return t.downloaded
	}
	return "{torrent} загрузился"
}

// telegram — заглушка Bot API, запоминающая последнюю форму.
type telegram struct {
	server *httptest.Server
	form   url.Values
	status int
	body   string
}

func newTelegram(t *testing.T) *telegram {
	t.Helper()
	tg := &telegram{status: http.StatusOK, body: `{"ok":true}`}
	tg.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tg.form = r.PostForm
		w.WriteHeader(tg.status)
		_, _ = io.WriteString(w, tg.body)
	}))
	t.Cleanup(tg.server.Close)
	return tg
}

func newNotifier(t *testing.T, tg *telegram, tmpl string) *tgnotify.Notifier {
	t.Helper()
	api := ""
	if tg != nil {
		api = tg.server.URL
	}
	return tgnotify.New(tgnotify.Config{
		Token: "123:abc", ChatID: "-1001",
		BaseURL: "http://inside.akiba.space:8080",
		APIBase: api,
	}, texts{tmpl: tmpl}, quiet())
}

// Без токена или чата бот обязан молчать, а не мешать работе шлюза.
func TestNotifierDisabledWithoutCredentials(t *testing.T) {
	for _, cfg := range []tgnotify.Config{
		{},
		{Token: "123:abc"},
		{ChatID: "-1001"},
	} {
		n := tgnotify.New(cfg, texts{}, quiet())
		if n.Enabled() {
			t.Fatalf("бот включился при конфигурации %+v", cfg)
		}
		if err := n.Notify(context.Background(), tgnotify.Event{TorrentName: "x"}); err != nil {
			t.Fatalf("выключенный бот вернул ошибку: %v", err)
		}
	}
}

func TestNotifierSendsMessage(t *testing.T) {
	tg := newTelegram(t)
	n := newNotifier(t, tg, "")

	err := n.Notify(context.Background(), tgnotify.Event{
		Username: "alice", DisplayName: "Алиса",
		TorrentName: "Ubuntu 24.04",
		Magnet:      "magnet:?xt=urn:btih:" + strings.Repeat("a", 40),
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if got := tg.form.Get("chat_id"); got != "-1001" {
		t.Errorf("chat_id = %q", got)
	}
	text := tg.form.Get("text")
	if !strings.Contains(text, "@alice") {
		t.Errorf("в сообщении нет ника: %q", text)
	}
	if !strings.Contains(text, "Ubuntu 24.04</a>") {
		t.Errorf("название торрента не стало текстом ссылки: %q", text)
	}
	if !strings.Contains(text, tgnotify.TorrentLinkPath+"?l=") {
		t.Errorf("ссылка ведёт не на шлюз: %q", text)
	}
	if strings.Contains(text, "magnet:") {
		t.Errorf("магнит попал в сообщение открытым текстом: %q", text)
	}
}

// Шаблон читается на каждую отправку: правка файла переводов обязана менять
// сообщения без перезапуска.
func TestNotifierReadsTemplateEveryTime(t *testing.T) {
	tg := newTelegram(t)
	n := newNotifier(t, tg, "{user} закачал {torrent}")

	if err := n.Notify(context.Background(), tgnotify.Event{Username: "bob", TorrentName: "X"}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if !strings.Contains(tg.form.Get("text"), "закачал") {
		t.Fatalf("шаблон не применён: %q", tg.form.Get("text"))
	}
}

// Ника может не быть — тогда показываем отображаемое имя.
func TestNotifierFallsBackToDisplayName(t *testing.T) {
	tg := newTelegram(t)
	n := newNotifier(t, tg, "")

	_ = n.Notify(context.Background(), tgnotify.Event{DisplayName: "Алиса", TorrentName: "X"})

	if !strings.Contains(tg.form.Get("text"), "Алиса") {
		t.Fatalf("не подставлено отображаемое имя: %q", tg.form.Get("text"))
	}
}

// Имя торрента приходит из чужого файла и может содержать разметку.
func TestNotifierEscapesTorrentName(t *testing.T) {
	tg := newTelegram(t)
	n := newNotifier(t, tg, "")

	_ = n.Notify(context.Background(), tgnotify.Event{
		Username: "alice", TorrentName: `<b>жирный</b>`, Magnet: "magnet:?xt=urn:btih:aa"})

	text := tg.form.Get("text")
	if strings.Contains(text, "<b>жирный</b>") {
		t.Fatalf("разметка из имени торрента ушла в сообщение как есть: %q", text)
	}
	if !strings.Contains(text, "&lt;b&gt;") {
		t.Fatalf("имя не экранировано: %q", text)
	}
}

// Без магнита ссылки быть не может — но сообщение всё равно уходит.
func TestNotifierWorksWithoutMagnet(t *testing.T) {
	tg := newTelegram(t)
	n := newNotifier(t, tg, "")

	if err := n.Notify(context.Background(), tgnotify.Event{Username: "alice", TorrentName: "X"}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if strings.Contains(tg.form.Get("text"), "<a href") {
		t.Fatalf("ссылка построена без магнита: %q", tg.form.Get("text"))
	}
}

func TestNotifierReportsTelegramError(t *testing.T) {
	tg := newTelegram(t)
	tg.status, tg.body = http.StatusBadRequest, `{"ok":false,"description":"chat not found"}`
	n := newNotifier(t, tg, "")

	err := n.Notify(context.Background(), tgnotify.Event{Username: "a", TorrentName: "X"})
	if err == nil {
		t.Fatal("ошибка Telegram проглочена")
	}
	if strings.Contains(err.Error(), "123:abc") {
		t.Fatalf("токен бота попал в текст ошибки: %v", err)
	}
}

// Токен стоит в пути Bot API, а http.Client оборачивает сетевую ошибку в
// url.Error, печатающий адрес целиком. Ошибка уходит в журнал — то есть при
// каждой недоступности Telegram токен оказывался бы в логе.
func TestNotifierHidesTokenInTransportError(t *testing.T) {
	n := tgnotify.New(tgnotify.Config{
		Token: "123456:СЕКРЕТНЫЙ", ChatID: "-1001",
		BaseURL: "http://inside.akiba.space:8080",
		// Порт 1 никто не слушает — гарантированная ошибка транспорта.
		APIBase: "http://127.0.0.1:1",
	}, texts{}, quiet())

	err := n.Notify(context.Background(), tgnotify.Event{Username: "a", TorrentName: "X"})
	if err == nil {
		t.Fatal("недоступный Telegram не дал ошибки")
	}
	if strings.Contains(err.Error(), "123456:СЕКРЕТНЫЙ") {
		t.Fatalf("токен бота в тексте ошибки: %v", err)
	}
}

// Telegram может вернуть токен в теле ошибки — вторая линия замены.
func TestNotifierHidesTokenInResponseBody(t *testing.T) {
	tg := newTelegram(t)
	tg.status, tg.body = http.StatusUnauthorized, `{"description":"bad token 123:abc"}`
	n := newNotifier(t, tg, "")

	err := n.Notify(context.Background(), tgnotify.Event{Username: "a", TorrentName: "X"})
	if err == nil {
		t.Fatal("ошибка проглочена")
	}
	if strings.Contains(err.Error(), "123:abc") {
		t.Fatalf("токен из тела ответа попал в ошибку: %v", err)
	}
}

// Сообщение приходит на каждый добавленный торрент, поэтому оно обязано быть
// беззвучным: иначе чат резидентов превращается в источник звона.
func TestNotifierSendsSilently(t *testing.T) {
	tg := newTelegram(t)
	n := newNotifier(t, tg, "")

	_ = n.Notify(context.Background(), tgnotify.Event{Username: "alice", TorrentName: "X"})

	if got := tg.form.Get("disable_notification"); got != "true" {
		t.Fatalf("disable_notification = %q, сообщение придёт со звуком", got)
	}
	if got := tg.form.Get("disable_web_page_preview"); got != "true" {
		t.Errorf("disable_web_page_preview = %q", got)
	}
}

// Сообщение о законченной загрузке уходит лично автору и, в отличие от
// сообщения в чат, со звуком: человек его ждёт, и адресат тут один.
func TestNotifierSendsDownloadedDirectly(t *testing.T) {
	tg := newTelegram(t)
	n := newNotifier(t, tg, "")

	if err := n.NotifyDownloaded(context.Background(), "42424242", "Ubuntu 24.04"); err != nil {
		t.Fatalf("NotifyDownloaded: %v", err)
	}

	// Адресат — сам резидент, а не групповой чат.
	if got := tg.form.Get("chat_id"); got != "42424242" {
		t.Fatalf("chat_id = %q, сообщение ушло не в личку", got)
	}
	if got := tg.form.Get("disable_notification"); got != "false" {
		t.Fatalf("disable_notification = %q, сообщение придёт без звука", got)
	}
	if text := tg.form.Get("text"); !strings.Contains(text, "Ubuntu 24.04") {
		t.Fatalf("в сообщении нет названия торрента: %q", text)
	}
}

// Личные сообщения работают и без TELEGRAM_CHAT_ID: адресат берётся из
// токена авторизации, а групповой чат для них не нужен.
func TestNotifierSendsDirectlyWithoutChatID(t *testing.T) {
	tg := newTelegram(t)
	n := tgnotify.New(tgnotify.Config{
		Token: "123:abc", APIBase: tg.server.URL,
	}, texts{}, quiet())

	if n.Enabled() {
		t.Fatal("бот считает себя настроенным на чат без TELEGRAM_CHAT_ID")
	}
	if !n.DirectEnabled() {
		t.Fatal("личные сообщения выключены при заданном токене")
	}
	if err := n.NotifyDownloaded(context.Background(), "42", "X"); err != nil {
		t.Fatalf("NotifyDownloaded: %v", err)
	}
	if got := tg.form.Get("chat_id"); got != "42" {
		t.Fatalf("chat_id = %q", got)
	}
}

// Без токена бот молчит и здесь — как и при отправке в чат.
func TestNotifierSkipsDirectMessageWithoutToken(t *testing.T) {
	n := tgnotify.New(tgnotify.Config{ChatID: "-1001"}, texts{}, quiet())

	if n.DirectEnabled() {
		t.Fatal("личные сообщения включились без токена")
	}
	if err := n.NotifyDownloaded(context.Background(), "42", "X"); err != nil {
		t.Fatalf("выключенный бот вернул ошибку: %v", err)
	}
}

// Имя торрента приходит из чужого файла и может содержать разметку — в личном
// сообщении она так же опасна, как и в чате.
func TestNotifierEscapesNameInDirectMessage(t *testing.T) {
	tg := newTelegram(t)
	n := newNotifier(t, tg, "")

	_ = n.NotifyDownloaded(context.Background(), "42", `<b>жирный</b>`)

	text := tg.form.Get("text")
	if strings.Contains(text, "<b>жирный</b>") {
		t.Fatalf("разметка из имени торрента ушла в сообщение как есть: %q", text)
	}
}

// Отказ Telegram обязан дойти до вызывающего: воркер по нему пишет в журнал,
// кому именно не удалось сообщить.
func TestNotifierReportsDirectMessageFailure(t *testing.T) {
	tg := newTelegram(t)
	tg.status, tg.body = http.StatusForbidden,
		`{"ok":false,"description":"bot can't initiate conversation with a user"}`
	n := newNotifier(t, tg, "")

	err := n.NotifyDownloaded(context.Background(), "42", "X")
	if err == nil {
		t.Fatal("отказ Telegram проглочен")
	}
	if strings.Contains(err.Error(), "123:abc") {
		t.Fatalf("токен бота попал в текст ошибки: %v", err)
	}
}

// Шаблон личного сообщения читается из файла переводов на каждую отправку.
func TestNotifierReadsDirectTemplateEveryTime(t *testing.T) {
	tg := newTelegram(t)
	n := tgnotify.New(tgnotify.Config{
		Token: "123:abc", ChatID: "-1001", APIBase: tg.server.URL,
	}, texts{downloaded: "готово: {torrent}"}, quiet())

	_ = n.NotifyDownloaded(context.Background(), "42", "Ubuntu")

	if got := tg.form.Get("text"); got != "готово: Ubuntu" {
		t.Fatalf("шаблон не применён: %q", got)
	}
}

// membershipTelegram — Bot API, отвечающий заданным статусом участника.
func membershipTelegram(t *testing.T, status int, body string) *telegram {
	t.Helper()
	tg := newTelegram(t)
	tg.status, tg.body = status, body
	return tg
}

func memberBody(status string, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return `{"ok":true,"result":{"status":"` + status + `"` + extra +
		`,"user":{"username":"alice","first_name":"Алиса","last_name":"Иванова"}}}`
}

// Кто считается состоящим в чате, а кто нет. Ошибка здесь означает либо
// вычищенных из базы живых резидентов, либо вечно висящих выбывших.
func TestChatMemberClassifiesStatuses(t *testing.T) {
	cases := []struct {
		status string
		extra  string
		want   tgnotify.Membership
	}{
		{"creator", "", tgnotify.MembershipIn},
		{"administrator", "", tgnotify.MembershipIn},
		{"member", "", tgnotify.MembershipIn},
		{"restricted", `"is_member":true`, tgnotify.MembershipIn},
		{"restricted", `"is_member":false`, tgnotify.MembershipOut},
		{"left", "", tgnotify.MembershipOut},
		{"kicked", "", tgnotify.MembershipOut},
	}
	for _, c := range cases {
		t.Run(c.status+c.extra, func(t *testing.T) {
			tg := membershipTelegram(t, http.StatusOK, memberBody(c.status, c.extra))
			n := newNotifier(t, tg, "")

			got, _, err := n.ChatMember(context.Background(), "42")
			if err != nil {
				t.Fatalf("ChatMember: %v", err)
			}
			if got != c.want {
				t.Fatalf("статус %q → %v, ожидалось %v", c.status, got, c.want)
			}
		})
	}
}

// Профиль приходит тем же запросом: второй вызов ради имени означал бы
// лишнее обращение к Telegram на каждого резидента.
func TestChatMemberReturnsProfile(t *testing.T) {
	tg := membershipTelegram(t, http.StatusOK, memberBody("member", ""))
	n := newNotifier(t, tg, "")

	_, profile, err := n.ChatMember(context.Background(), "42")
	if err != nil {
		t.Fatalf("ChatMember: %v", err)
	}
	if profile.Username != "alice" || profile.FirstName != "Алиса" || profile.LastName != "Иванова" {
		t.Fatalf("профиль = %+v", profile)
	}
}

// Незнакомый статус — это «не знаем», а не «выбыл»: Telegram волен завести
// новый, и удалять по нему людей нельзя.
func TestChatMemberTreatsUnknownStatusAsUnknown(t *testing.T) {
	tg := membershipTelegram(t, http.StatusOK, memberBody("телепортировался", ""))
	n := newNotifier(t, tg, "")

	got, _, err := n.ChatMember(context.Background(), "42")
	if err == nil {
		t.Fatal("незнакомый статус принят молча")
	}
	if got != tgnotify.MembershipUnknown {
		t.Fatalf("статус = %v, ожидался MembershipUnknown", got)
	}
}

// «user not found» — законный ответ: такого резидента Telegram не знает,
// и в чате его точно нет.
func TestChatMemberTreatsMissingUserAsOut(t *testing.T) {
	tg := membershipTelegram(t, http.StatusBadRequest,
		`{"ok":false,"description":"Bad Request: user not found"}`)
	n := newNotifier(t, tg, "")

	got, _, err := n.ChatMember(context.Background(), "42")
	if err != nil {
		t.Fatalf("ChatMember: %v", err)
	}
	if got != tgnotify.MembershipOut {
		t.Fatalf("статус = %v, ожидался MembershipOut", got)
	}
}

// Прочие отказы Telegram — это «не знаем»: по ним удалять нельзя.
func TestChatMemberReportsTelegramRefusal(t *testing.T) {
	tg := membershipTelegram(t, http.StatusBadRequest,
		`{"ok":false,"description":"Bad Request: chat not found"}`)
	n := newNotifier(t, tg, "")

	got, _, err := n.ChatMember(context.Background(), "42")
	if err == nil {
		t.Fatal("отказ Telegram проглочен")
	}
	if got != tgnotify.MembershipUnknown {
		t.Fatalf("статус = %v", got)
	}
	if strings.Contains(err.Error(), "123:abc") {
		t.Fatalf("токен в тексте ошибки: %v", err)
	}
}

func TestChatMemberFailsOnBrokenJSON(t *testing.T) {
	tg := membershipTelegram(t, http.StatusOK, "не json")
	n := newNotifier(t, tg, "")

	got, _, err := n.ChatMember(context.Background(), "42")
	if err == nil {
		t.Fatal("битый JSON принят")
	}
	if got != tgnotify.MembershipUnknown {
		t.Fatalf("статус = %v", got)
	}
}

// Без настроенного чата спрашивать не у кого — но и ошибкой это не является:
// шлюз обязан работать с выключенным ботом.
func TestChatMemberIsQuietWithoutChat(t *testing.T) {
	n := tgnotify.New(tgnotify.Config{Token: "123:abc"}, texts{}, quiet())

	got, _, err := n.ChatMember(context.Background(), "42")
	if err != nil {
		t.Fatalf("выключенный бот вернул ошибку: %v", err)
	}
	if got != tgnotify.MembershipUnknown {
		t.Fatalf("статус = %v", got)
	}
}
