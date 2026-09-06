// Package admin — управление резидентами: кому какие сервисы доступны.
//
// Страница одна и намеренно простая: список людей, у каждого справа перечень
// выданных сервисов, по нажатию — галочки. Ни поиска, ни постраничности:
// резидентов десятки, и всё, что сложнее списка, здесь было бы работой на
// вырост, которая устареет раньше, чем понадобится.
//
// Права на саму админку выдаются так же, как на остальные сервисы, — через
// неё же. Поэтому в конфигурации есть администратор, которого нельзя лишить
// доступа: без него первая же ошибка в галочках заперла бы систему.
package admin

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/audit"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/i18n"
)

// Path — публичный адрес админки.
const Path = "/admin"

//go:embed templates/admin.html
var templatesFS embed.FS

var pageTemplate = template.Must(template.ParseFS(templatesFS, "templates/admin.html"))

// Store — то, что нужно админке от базы.
type Store interface {
	Residents(ctx context.Context) ([]audit.Resident, error)
	SetResidentServices(ctx context.Context, telegramID string, services []string) error
}

// Texts отдаёт тексты интерфейса.
type Texts interface {
	Messages() i18n.Messages
}

// Reconciler сверяет список с составом группового чата.
type Reconciler interface {
	Trigger(ctx context.Context) bool
}

// Handler отдаёт админку.
type Handler struct {
	Store   Store
	Texts   Texts
	Catalog access.Catalog
	// Hosts — под какими именами портал считается своим. По ним проверяется
	// происхождение POST: без этого любой открытый администратором сайт мог
	// бы отправить сюда форму от его имени и выдать себе все права.
	Hosts auth.HostPolicy
	// RootAdmin — Telegram-ID администратора из конфигурации. Его карточка не
	// нажимается, права ему не показываются и не меняются.
	RootAdmin string
	// Reconcile запускается при открытии списка. Может быть nil: без бота
	// сверять состав чата не с чем.
	Reconcile Reconciler
	Log       *slog.Logger
}

// viewModel — данные страницы.
type viewModel struct {
	M         i18n.Messages
	Residents []residentView
	// Editing — резидент, у которого сейчас открыты галочки. Пусто, если
	// открыт просто список.
	Editing  *residentView
	Services []serviceView
	Error    string
	Saved    bool
}

type residentView struct {
	TelegramID  string
	DisplayName string
	Username    string
	// Tags — выданные сервисы в виде подписанных плашек справа от имени.
	Tags []serviceTag
	// Services — идентификаторы выданных сервисов. Носим их с собой, а не
	// достаём по индексу из исходного среза: любая будущая фильтрация в
	// views() рассыпала бы такое соответствие молча, и галочки открывались бы
	// от чужого человека. Компилятор такую ошибку не поймает.
	Services []string
	// Root — тот самый администратор из конфигурации.
	Root bool
}

type serviceView struct {
	ID      string
	Title   string
	Checked bool
}

// serviceTag — плашка сервиса в списке резидентов.
//
// Класс подставляется в разметку, а не цвет: цвета живут в одном месте, в
// таблице стилей страницы, и подобрать их там можно, не трогая Go.
type serviceTag struct {
	Title string
	Class string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost:
		h.save(w, r)
	case r.Method == http.MethodGet:
		h.list(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
	}
}

// list рисует список резидентов, при необходимости с открытыми галочками.
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	// Сверка уходит в фон и на страницу не влияет: она ходит в Telegram по
	// запросу на каждого резидента, и ждать её значило бы открывать админку
	// секундами. О выбывших станет известно на следующем открытии.
	if h.Reconcile != nil {
		h.Reconcile.Trigger(r.Context())
	}

	m := h.Texts.Messages()
	residents, err := h.Store.Residents(r.Context())
	if err != nil {
		h.Log.Error("не удалось прочитать список резидентов", "error", err)
		h.render(w, viewModel{M: m, Error: m.AdminLoadError}, http.StatusInternalServerError)
		return
	}

	vm := viewModel{M: m, Residents: h.views(residents, m)}
	if edit := strings.TrimSpace(r.URL.Query().Get("user")); edit != "" {
		i := slices.IndexFunc(vm.Residents, func(v residentView) bool { return v.TelegramID == edit })
		switch {
		case i < 0:
			vm.Error = m.AdminUnknownResident
		case vm.Residents[i].Root:
			// Карточку администратора не открываем даже по прямой ссылке:
			// иначе запрет на нажатие был бы чисто оформительским.
			vm.Error = m.AdminRootLocked
		default:
			vm.Editing = &vm.Residents[i]
			vm.Services = h.serviceViews(vm.Residents[i].Services, m)
		}
	}
	if r.URL.Query().Get("saved") == "1" {
		vm.Saved = true
	}
	h.render(w, vm, http.StatusOK)
}

// save применяет галочки.
func (h *Handler) save(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "некорректная форма", http.StatusBadRequest)
		return
	}
	// Проверка происхождения. Это самый привилегированный POST в системе:
	// им раздаются права, включая права администратора. Куку ставит внешний
	// auth-service, её атрибуты нам не подчиняются (DEPLOY.md прямо говорит,
	// что она без Secure), поэтому полагаться на SameSite нельзя — проверяем
	// сами, ровно как это делает прокси qBittorrent.
	if reason, blocked := h.crossSite(r); blocked {
		h.Log.Warn("изменение прав отклонено как межсайтовый запрос",
			"actor", actorOf(r), "reason", reason)
		http.Error(w, "межсайтовый запрос отклонён", http.StatusForbidden)
		return
	}

	target := strings.TrimSpace(r.PostFormValue("user"))
	if target == "" {
		http.Error(w, "не указан резидент", http.StatusBadRequest)
		return
	}
	// Администратора из конфигурации не трогаем ничем: у него всегда всё, и
	// запись сюда была бы записью, которую политика всё равно игнорирует, —
	// то есть враньём в базе.
	if target == h.RootAdmin {
		h.Log.Warn("попытка изменить права администратора из конфигурации",
			"actor", actorOf(r), "target", "tg"+target)
		http.Error(w, "права администратора из конфигурации изменить нельзя", http.StatusForbidden)
		return
	}

	// Принимаем только известные сервисы: в форму можно дописать что угодно,
	// и без фильтра эта строка уехала бы прямо в базу.
	var services []string
	for _, raw := range r.PostForm["service"] {
		if id := access.ID(raw); access.Known(id) {
			services = append(services, raw)
		} else {
			h.Log.Warn("в форме админки пришёл неизвестный сервис",
				"actor", actorOf(r), "service", raw)
		}
	}

	if err := h.Store.SetResidentServices(r.Context(), target, services); err != nil {
		// Несуществующий резидент — это ошибка запроса, а не сбой сервиса.
		// Отдавать на неё 500 значило бы поднимать оператора на опечатку.
		if errors.Is(err, audit.ErrNoResident) {
			h.Log.Warn("права выданы несуществующему резиденту",
				"actor", actorOf(r), "target", "tg"+target)
			http.Error(w, "такого резидента нет", http.StatusNotFound)
			return
		}
		h.Log.Error("не удалось сохранить права резидента",
			"error", err, "actor", actorOf(r), "target", "tg"+target)
		http.Error(w, "не удалось сохранить", http.StatusInternalServerError)
		return
	}
	h.Log.Info("права резидента изменены",
		"actor", actorOf(r), "target", "tg"+target, "services", strings.Join(services, ","))

	// Redirect после POST: обновление страницы не должно переотправлять форму.
	w.Header().Set("Cache-Control", "no-store, private")
	http.Redirect(w, r, Path+"?user="+target+"&saved=1", http.StatusSeeOther)
}

// crossSite решает, пришёл ли запрос с чужой страницы.
//
// Проверяются два независимых признака: Origin (браузеры шлют его на всех
// небезопасных методах) и Sec-Fetch-Site (шлют современные). Отсутствие
// обоих означает не браузер, а программного клиента — например, curl
// администратора; такой запрос пропускаем, потому что подделать его с чужой
// страницы всё равно нельзя.
func (h *Handler) crossSite(r *http.Request) (string, bool) {
	self, _ := h.Hosts.Origin(r)
	if origin := r.Header.Get("Origin"); origin != "" && origin != self {
		return "origin " + origin, true
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return "sec-fetch-site " + r.Header.Get("Sec-Fetch-Site"), true
	}
	return "", false
}

// views переводит резидентов в то, что показывает страница.
func (h *Handler) views(residents []audit.Resident, m i18n.Messages) []residentView {
	out := make([]residentView, 0, len(residents))
	for _, r := range residents {
		v := residentView{
			TelegramID:  r.TelegramID,
			DisplayName: r.DisplayName(),
			Username:    r.Username,
			Root:        h.RootAdmin != "" && r.TelegramID == h.RootAdmin,
		}
		// У администратора список справа не показываем намеренно: ему
		// доступно всё и всегда, и перечисление создавало бы впечатление,
		// что этот набор кто-то ему выдал и может отобрать.
		if !v.Root {
			v.Services = append([]string(nil), r.Services...)
			v.Tags = h.tagsOf(r.Services, m)
		}
		out = append(out, v)
	}
	return out
}

// serviceViews собирает галочки: все известные сервисы с отметками выданных.
func (h *Handler) serviceViews(granted []string, m i18n.Messages) []serviceView {
	out := make([]serviceView, 0, len(access.All()))
	for _, id := range access.All() {
		svc, ok := h.Catalog.Describe(id, m)
		if !ok {
			continue
		}
		out = append(out, serviceView{
			ID:      string(id),
			Title:   svc.Title,
			Checked: slices.Contains(granted, string(id)),
		})
	}
	return out
}

// tagsOf собирает плашки выданных сервисов, в порядке All().
func (h *Handler) tagsOf(granted []string, m i18n.Messages) []serviceTag {
	var out []serviceTag
	for _, id := range access.All() {
		if !slices.Contains(granted, string(id)) {
			continue
		}
		svc, ok := h.Catalog.Describe(id, m)
		if !ok {
			continue
		}
		out = append(out, serviceTag{Title: svc.Title, Class: tagClass(id)})
	}
	return out
}

// tagClass выбирает оформление плашки по сервису.
//
// Каждому сервису — свой цвет, чтобы набор прав читался с одного взгляда, не
// вчитываясь в названия. Права администратора выделены отдельно и заметно:
// это единственная строка в списке, из-за которой человек получает власть над
// доступом остальных, и не заметить её при беглом просмотре нельзя.
//
// Соответствие задано явно, а не выведено из идентификатора: цвет — решение
// оформления, и принимать его должен человек, а не формула.
func tagClass(id access.ID) string {
	switch id {
	case access.Jellyfin:
		return "tag-jellyfin"
	case access.QBittorrent:
		return "tag-qbit"
	case access.Nextcloud:
		return "tag-nextcloud"
	case access.Admin:
		return "tag-admin"
	default:
		return "tag-other"
	}
}

func (h *Handler) render(w http.ResponseWriter, vm viewModel, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, private")
	auth.OwnPageHeaders(w.Header())
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, vm); err != nil {
		h.Log.Error("не удалось отрендерить админку", "error", err)
	}
}

// actorOf — кто именно совершает действие. Для журнала: правки прав обязаны
// быть именными, иначе разобрать, кто кому что открыл, будет невозможно.
func actorOf(r *http.Request) string {
	if claims, ok := auth.FromContext(r.Context()); ok {
		return claims.UID()
	}
	return "аноним"
}
