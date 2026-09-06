package app

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/admin"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/directory"
	"github.com/akiba-hs/akiba-gate/internal/jellyfin"
	"github.com/akiba-hs/akiba-gate/internal/nextcloud"
	"github.com/akiba-hs/akiba-gate/internal/portal"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
	"github.com/akiba-hs/akiba-gate/internal/userpic"
)

// Deps — всё, что нужно маршрутизатору. Собирается в main.
type Deps struct {
	Log         *slog.Logger
	ForwardAuth *auth.ForwardAuth
	Portal      *portal.Handler
	// Policy решает, кому какой сервис доступен. Спрашивается не только
	// порталом для показа карточек, но и здесь: адрес сервиса можно набрать
	// руками, и без проверки на маршруте персональный доступ был бы
	// косметикой.
	Policy access.Policy

	JellyfinSSO      http.Handler
	JellyfinProxy    http.Handler
	JellyfinBasePath string
	JellyfinConnect  http.Handler
	JellyfinApprove  http.Handler

	QbitProxy    http.Handler
	QbitBasePath string

	// NextcloudOpen — страница-перемычка перед выдачей кода. Нужна затем же,
	// зачем такая же у Jellyfin: переход занимает секунды, и без неё человек
	// смотрит на прежний экран и жмёт карточку второй раз, сжигая код.
	NextcloudOpen http.Handler
	// NextcloudSSO выдаёт одноразовый код и отправляет браузер в Nextcloud.
	NextcloudSSO http.Handler
	// NextcloudRedeem обменивает код на личность по запросу приложения
	// внутри Nextcloud. Единственный маршрут шлюза, который защищён не кукой
	// резидента, а общим секретом: обращается к нему сервер, а не браузер.
	NextcloudRedeem http.Handler

	// Admin — управление резидентами.
	Admin http.Handler

	UserPic     http.Handler
	TorrentLink http.Handler

	// Residents запоминает вошедшего. Может быть nil в тестах.
	Residents *directory.Recorder
}

// NewRouter собирает дерево маршрутов шлюза.
//
// Все защищённые обработчики завёрнуты в Guard, который сам проверяет JWT.
// Traefik с его forwardAuth — первый рубеж, Guard — второй: неверно собранный
// middleware в прокси не должен открывать доступ. Право на конкретный сервис
// проверяется третьим слоем — access.Require.
func NewRouter(d Deps) http.Handler {
	mux := http.NewServeMux()
	guard := d.ForwardAuth.Guard

	// service оборачивает сервис проверкой права и записью перехода в журнал.
	//
	// Порядок слоёв важен. Guard опознаёт человека, noteResident записывает
	// его в список (иначе он никогда не появился бы в админке), и только
	// потом проверяется право: отказ в доступе — не причина «не знать» о
	// человеке, наоборот, именно таких и надо показать администратору.
	service := func(id access.ID, h http.Handler) http.Handler {
		return guard(noteResident(d.Residents,
			access.Require(d.Policy, id, d.Log, logEntry(d.Log, id, h))))
	}

	// Портал опрашивает этот адрес, пока человек входит в соседней вкладке.
	mux.HandleFunc("GET /whoami", d.Portal.WhoAmI)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	// Эндпоинт для middleware forwardAuth в Traefik.
	mux.Handle("/verify", d.ForwardAuth)

	// Переход на магнит-ссылку из сообщения бота. Без авторизации намеренно:
	// ссылку открывают из группового чата.
	if d.TorrentLink != nil {
		mux.Handle("GET "+tgnotify.TorrentLinkPath, d.TorrentLink)
	}

	// Аватарки Telegram через шлюз. За Guard: открытый прокси к чужому
	// домену нам не нужен.
	if d.UserPic != nil {
		mux.Handle("GET "+userpic.Path, guard(d.UserPic))
	}

	// --- Jellyfin ---------------------------------------------------------
	mux.Handle("GET /sso/jellyfin", service(access.Jellyfin, d.JellyfinSSO))
	if d.JellyfinConnect != nil {
		connect := service(access.Jellyfin, d.JellyfinConnect)
		mux.Handle("GET "+jellyfin.QuickConnectPath, connect)
		mux.Handle("POST "+jellyfin.QuickConnectPath, connect)
	}
	if d.JellyfinApprove != nil {
		mux.Handle("POST "+jellyfin.QuickConnectApprovePath,
			service(access.Jellyfin, d.JellyfinApprove))
	}
	if d.JellyfinBasePath != "" && d.JellyfinProxy != nil {
		proxy := service(access.Jellyfin, d.JellyfinProxy)
		mux.Handle(d.JellyfinBasePath, proxy)
		mux.Handle(d.JellyfinBasePath+"/", proxy)
	}

	// --- qBittorrent ------------------------------------------------------
	if d.QbitBasePath != "" && d.QbitProxy != nil {
		proxy := service(access.QBittorrent, d.QbitProxy)
		mux.Handle(d.QbitBasePath, proxy)
		mux.Handle(d.QbitBasePath+"/", proxy)
	}

	// --- Nextcloud --------------------------------------------------------
	// Обмен кода регистрируется раньше остальных маршрутов Nextcloud: он
	// более специфичен, и ServeMux обязан отдать его именно этому
	// обработчику, а не общему префиксу.
	if d.NextcloudRedeem != nil {
		mux.Handle("POST "+nextcloud.RedeemPath, d.NextcloudRedeem)
	}
	// Перемычка регистрируется раньше общего префикса и без записи в журнал
	// перехода: сам переход зафиксирует StartHandler строкой ниже.
	if d.NextcloudOpen != nil {
		mux.Handle("GET "+nextcloud.OpenPath,
			guard(noteResident(d.Residents,
				access.Require(d.Policy, access.Nextcloud, d.Log, d.NextcloudOpen))))
	}
	if d.NextcloudSSO != nil {
		sso := service(access.Nextcloud, d.NextcloudSSO)
		// Только точные адреса: с поддеревом любой путь под /nextcloud/
		// выдавал бы и сжигал одноразовый код.
		mux.Handle("GET "+nextcloud.StartPath, sso)
		mux.Handle("GET "+nextcloud.StartPath+"/{$}", sso)
	}

	// --- Управление резидентами -------------------------------------------
	if d.Admin != nil {
		panel := service(access.Admin, d.Admin)
		mux.Handle("GET "+admin.Path, panel)
		mux.Handle("POST "+admin.Path, panel)
	}

	// Портал последним: он же отдаёт 404 на всё неизвестное.
	mux.Handle("/", d.Portal)

	// accessLog снаружи recoverPanic: иначе запрос, уронивший обработчик,
	// не оставлял бы строки в журнале доступа — ровно тот запрос, который
	// потом и приходится искать.
	return accessLog(d.Log, recoverPanic(d.Log, securityHeaders(mux)))
}

// noteResident записывает вошедшего в список резидентов.
//
// Стоит на маршрутах сервисов, а не только на портале: человек может прийти
// сразу по адресу сервиса, и без этого он не появился бы в админке, пока не
// заглянет на главную. Запись дешёвая — в базу она уходит, только когда
// данные изменились (см. directory.Recorder).
func noteResident(rec *directory.Recorder, next http.Handler) http.Handler {
	if rec == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims, ok := auth.FromContext(r.Context()); ok {
			rec.Note(r.Context(), claims)
		}
		next.ServeHTTP(w, r)
	})
}

// logEntry пишет в журнал переход резидента в сервис.
//
// Только на входной точке — на корне префикса: веб-интерфейсы шлют десятки
// подзапросов в секунду, и запись на каждый превратила бы журнал в шум.
func logEntry(log *slog.Logger, id access.ID, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isEntryPoint(r.URL.Path) {
			user := "аноним"
			if claims, ok := auth.FromContext(r.Context()); ok {
				user = claims.UID()
			}
			log.Info("резидент перешёл в сервис",
				"user", user, "service", string(id))
		}
		next.ServeHTTP(w, r)
	})
}

// isEntryPoint отличает вход в сервис от его внутренних запросов.
func isEntryPoint(path string) bool {
	switch path {
	case "/sso/jellyfin", "/nextcloud", "/nextcloud/", admin.Path:
		return true
	}
	// Корень префикса сервиса: "/qbittorrent/", "/jellyfin/".
	return len(path) > 1 && path[len(path)-1] == '/' &&
		strings.Count(path, "/") == 2
}
