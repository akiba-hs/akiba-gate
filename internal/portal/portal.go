// Package portal рендерит стартовую страницу шлюза.
//
// Страница обязана собираться на сервере: кука авторизации помечена HttpOnly,
// поэтому клиентский JavaScript её не видит и не может решить, показывать
// ссылки или нет. Побочная польза — ссылки на сервисы попросту отсутствуют в
// HTML для неавторизованного посетителя, их нельзя подсмотреть в исходнике.
//
// Какие именно сервисы показывать, портал не решает: он спрашивает у
// access.Policy. Так список карточек и право зайти по адресу сервиса всегда
// берутся из одного источника.
package portal

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/directory"
	"github.com/akiba-hs/akiba-gate/internal/i18n"
	"github.com/akiba-hs/akiba-gate/internal/userpic"
)

//go:embed templates/index.html
var templatesFS embed.FS

var indexTemplate = template.Must(template.ParseFS(templatesFS, "templates/index.html"))

// Texts отдаёт тексты интерфейса. Интерфейс, а не структура, чтобы портал
// тестировался без файла на диске.
type Texts interface {
	Messages() i18n.Messages
}

// Handler отдаёт портал.
type Handler struct {
	Verifier   *auth.Verifier
	CookieName string
	AuthURL    *url.URL
	Hosts      auth.HostPolicy
	// Policy решает, какие сервисы доступны конкретному человеку.
	Policy access.Policy
	// Catalog знает адреса сервисов; названия берутся из Texts.
	Catalog access.Catalog
	Texts   Texts
	// ReturnBase, если задан, заменяет схему и хост в адресе возврата после
	// входа. См. пояснение в auth.ForwardAuth.
	ReturnBase *url.URL
	// ProxyUserPics — отдавать ли аватарки через собственный /userpic/.
	//
	// Включается вместе с SOCKS5: прослойка нужна там, где прямой выход в
	// t.me закрыт. Без прокси шлюз всё равно ходил бы в Telegram напрямую,
	// только лишним звеном — с задержкой на каждый заход и с трафиком через
	// себя. Поэтому при пустом SOCKS5_PROXY браузер идёт за картинкой сам,
	// а утечку адреса портала в Referer снимает referrerpolicy в шаблоне.
	ProxyUserPics bool
	// Audience отмечает, что человека уже видели: нужно, чтобы «вошёл в
	// систему» попадало в журнал один раз, а не на каждый запрос.
	Audience *auth.Seen
	// Residents заносит вошедшего в список резидентов. Может быть nil:
	// портал обязан открываться и без базы.
	Residents *directory.Recorder
	Log       *slog.Logger
}

type viewModel struct {
	M             i18n.Messages
	Authenticated bool
	IsResident    bool
	DisplayName   string
	Username      string
	PhotoURL      string
	// PhotoProxied — картинка идёт через шлюз, а не прямо из Telegram.
	// Шаблону нужно, чтобы решить, ставить ли referrerpolicy.
	PhotoProxied bool
	Services     []access.Service
	LoginURL     string
	LogoutURL    string
	Error        string
	// ReturnsElsewhere — вход возвращает человека вообще не к нам. Так
	// бывает, когда AUTH_RETURN_BASE_URL указывает на чужой адрес (например,
	// на страницу самого auth-service). Тогда портал открывает вход в
	// соседней вкладке и ждёт куку опросом /whoami. Если же адрес возврата
	// наш, пусть и другой, — возвращаться будет сюда, и вся эта механика ни
	// к чему.
	ReturnsElsewhere bool
	// CanonicalURL заполнен, только когда портал открыли не по тому имени.
	CanonicalURL string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Портал — единственная страница на хосте, которая обязана открываться
	// без авторизации, поэтому маршрут точный: всё остальное на этом уровне 404.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	m := h.Texts.Messages()
	vm := viewModel{
		M:         m,
		LoginURL:  h.loginURL(r),
		LogoutURL: h.AuthURL.String() + "/logout",
	}
	switch r.URL.Query().Get("error") {
	case "not_resident":
		vm.Error = m.NotResidentError
	}
	vm.ReturnsElsewhere = h.ReturnBase != nil && !h.Hosts.Allows(h.ReturnBase.Host)
	if _, ok := h.Hosts.Origin(r); !ok && h.Hosts.Base != nil {
		vm.CanonicalURL = h.Hosts.Base.Scheme + "://" + h.Hosts.Base.Host + "/"
	}

	claims := h.claims(r)
	if claims != nil {
		h.noteLogin(claims)
		// Список резидентов пополняется здесь, а не по событию входа:
		// собственного события входа у шлюза нет — вход делает auth-service.
		h.Residents.Note(r.Context(), claims)
		vm.Authenticated = true
		vm.IsResident = claims.IsResident
		vm.DisplayName = claims.DisplayName()
		vm.Username = claims.Username
		vm.PhotoURL = h.photoURL(claims.PhotoURL)
		// Смотрим на итоговый адрес, а не на настройку: Rewrite намеренно
		// пропускает чужие адреса как есть, и с включённым прокси в src мог
		// бы оказаться посторонний хост — как раз тот случай, ради которого
		// referrerpolicy и нужен.
		vm.PhotoProxied = strings.HasPrefix(vm.PhotoURL, userpic.Path)
		services, err := access.ServicesFor(r.Context(), h.Policy, h.Catalog, m, claims)
		if err != nil {
			// Список не собрался — показываем портал без карточек и говорим
			// об этом в журнал. Молча показать пустой портал нельзя: он
			// выглядит ровно как «у тебя нет доступа».
			h.Log.Error("не удалось собрать список сервисов",
				"user", claims.UID(), "error", err)
		}
		vm.Services = services
		h.Log.Info("резидент открыл главную страницу",
			"user", claims.UID(), "username", claims.Username,
			"services", len(vm.Services))
	} else {
		h.Log.Info("главную страницу открыл анонимный посетитель")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Страница персональная: общий кэш её сохранять не должен.
	w.Header().Set("Cache-Control", "no-store, private")
	auth.OwnPageHeaders(w.Header())
	if err := indexTemplate.Execute(w, vm); err != nil {
		h.Log.Error("не удалось отрендерить портал", "error", err)
	}
}

// noteLogin пишет в журнал факт входа один раз на человека.
//
// Отдельного события «вошёл» у шлюза нет: вход делает auth-service, а сюда
// приходит уже готовая кука. Поэтому за вход считаем первую встречу с этим
// Telegram-ID после запуска — иначе строка «авторизовался» повторялась бы на
// каждый запрос и перестала бы что-либо значить.
func (h *Handler) noteLogin(c *auth.Claims) {
	if h.Audience == nil || !h.Audience.First(c.UID()) {
		return
	}
	h.Log.Info("человек авторизовался в системе",
		"user", c.UID(), "username", c.Username,
		"display_name", c.DisplayName(), "resident", c.IsResident)
}

// WhoAmI отвечает, действует ли сейчас кука авторизации.
//
// Нужен ровно для одного: портал открыт в одной вкладке, вход происходит в
// другой, и вернуть человека обратно auth-service не может — он отказывается
// возвращать на адрес с нестандартным портом. Кука при этом выдаётся на весь
// домен и до портала доходит, поэтому вкладка опрашивает этот адрес и
// обновляет себя сама, как только вход состоялся.
//
// Наружу отдаётся только факт про самого спрашивающего, поэтому маршрут
// открыт: чужую личность здесь не узнать.
func (h *Handler) WhoAmI(w http.ResponseWriter, r *http.Request) {
	claims := h.claims(r)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, private")
	body := `{"authenticated":false,"resident":false}`
	if claims != nil {
		body = fmt.Sprintf(`{"authenticated":true,"resident":%t}`, claims.IsResident)
	}
	_, _ = io.WriteString(w, body)
}

func (h *Handler) claims(r *http.Request) *auth.Claims {
	cookie, err := r.Cookie(h.CookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	claims, err := h.Verifier.Verify(cookie.Value)
	if err != nil {
		// Протухший или чужой токен — показываем портал как анонимному.
		h.Log.Debug("портал: токен отклонён", "error", err)
		return nil
	}
	return claims
}

// loginURL ведёт на auth-service с возвратом на портал.
//
// Хост берётся только из проверенного Origin: иначе запрос с подставленным
// Host даёт ссылку на настоящий auth.akiba.space с чужим адресом возврата.
func (h *Handler) loginURL(r *http.Request) string {
	origin, ok := h.Hosts.Origin(r)
	if !ok {
		h.Log.Warn("возврат на посторонний хост отклонён", "forwarded_host", auth.RequestHost(r))
	}
	target := origin + "/"
	if h.ReturnBase != nil {
		target = auth.ReturnTarget(h.ReturnBase)
	}
	u := *h.AuthURL
	q := u.Query()
	q.Set("redirect_uri", target)
	u.RawQuery = q.Encode()
	return u.String()
}

// photoURL готовит адрес аватарки для страницы.
//
// Через шлюз — только когда задан SOCKS5: там прослойка и есть весь смысл,
// потому что у части резидентов t.me не открывается. При прямом выходе тот же
// запрос браузер сделает быстрее и без нагрузки на шлюз.
func (h *Handler) photoURL(raw string) string {
	safe := safePhotoURL(raw)
	if !h.ProxyUserPics {
		return safe
	}
	return userpic.Rewrite(safe)
}

// safePhotoURL пропускает только http(s)-ссылки.
//
// В токен URL попадает из данных Telegram, но токен подписан не нами — если
// когда-нибудь появится второй эмитент, лучше не давать вставить в src
// произвольную схему вроде javascript:.
func safePhotoURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return raw
}
