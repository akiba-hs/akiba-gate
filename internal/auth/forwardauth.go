package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// ForwardAuth реализует эндпоинт для Traefik-middleware forwardAuth.
//
// Контракт Traefik: ответ 2xx — запрос пропускается дальше (заголовки из
// authResponseHeaders копируются в проксируемый запрос); любой другой ответ
// целиком отдаётся клиенту. Поэтому редирект на страницу входа мы возвращаем
// прямо отсюда.
type ForwardAuth struct {
	Verifier      *Verifier
	CookieName    string
	AuthURL       *url.URL // https://auth.akiba.space
	PublicBaseURL *url.URL // https://inside.akiba.space
	// AllowedHosts — хосты, на которые разрешено возвращать человека
	// после входа. Заголовок X-Forwarded-Host приходит извне, и без списка
	// им можно подсунуть ссылку вида
	// auth.akiba.space/?redirect_uri=https://evil.example — внешне
	// легитимную. PublicBaseURL считается разрешённым всегда.
	AllowedHosts []string
	// ReturnBase, если задан, целиком заменяет адрес возврата после входа —
	// вместе с путём. Нужен потому, что auth-service проверяет redirect_uri
	// как netloc.endswith(".akiba.space"), а netloc включает порт: с портала
	// на нестандартном порту вход иначе заканчивается ошибкой 400 Invalid
	// redirect_uri.
	//
	// Путь исходного запроса при этом теряется, и это осознанно: адресом
	// возврата в такой ситуации служит посторонняя страница (например, сам
	// auth-service), и подставлять ей чужой путь — значит привести человека
	// на её 404. Возврат к нужному разделу — цена за возможность войти
	// вообще; без настройки поведение прежнее, и глубокая ссылка сохраняется.
	ReturnBase      *url.URL
	RequireResident bool
	// RootAdmin — Telegram-ID администратора из конфигурации. Он проходит
	// проверку на резидентство всегда.
	//
	// Без этого исключения остальной код врал бы: политика доступа выдаёт ему
	// все сервисы даже при недоступной базе, сверка состава чата отказывается
	// его удалять — а сюда он не дошёл бы вовсе, выйдя из чата на день. Два
	// слоя, расходящиеся в том, кто такой администратор, рано или поздно
	// расходятся в чью-то пользу.
	RootAdmin string
	Log       *slog.Logger
}

// withReturnBase подменяет адрес возврата настроенным, если он задан.
func (f *ForwardAuth) withReturnBase(raw string) string {
	if f.ReturnBase == nil {
		return raw
	}
	return ReturnTarget(f.ReturnBase)
}

// ReturnTarget приводит настроенный адрес возврата к пригодному для
// redirect_uri виду: без пустого пути, который auth-service увидит как "".
func ReturnTarget(base *url.URL) string {
	u := *base
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// Hosts собирает политику имён хостов из полей шлюза.
func (f *ForwardAuth) Hosts() HostPolicy {
	return HostPolicy{Base: f.PublicBaseURL, Allowed: f.AllowedHosts}
}

func (f *ForwardAuth) allowedHost(host string) bool { return f.Hosts().Allows(host) }

// returnURL строит адрес возврата, отбрасывая чужие хосты.
func (f *ForwardAuth) returnURL(r *http.Request) string {
	if _, ok := f.Hosts().Origin(r); !ok {
		f.Log.Warn("возврат на посторонний хост отклонён", "forwarded_host", RequestHost(r))
		return f.portalURL("")
	}
	return OriginalURL(r, f.PublicBaseURL)
}

func (f *ForwardAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Никогда не доверяем заголовкам идентичности, пришедшим извне.
	StripIdentityHeaders(r.Header)

	claims, err := f.authenticate(r)
	switch {
	case err == nil:
		SetIdentityHeaders(w.Header(), claims)
		// Ответ ForwardAuth не должен кэшироваться промежуточными узлами:
		// иначе чужая личность «залипнет» на общем кэше.
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)

	case errors.Is(err, ErrNotResident):
		// На страницу входа отправлять нельзя: токен валиден, auth-service
		// сразу вернёт человека обратно — получится вечный цикл.
		// Ведём на портал, он объяснит, что доступ только для резидентов.
		f.redirect(w, r, f.portalURL("not_resident"), http.StatusFound)

	default:
		f.Log.Debug("доступ отклонён", "error", err, "url", OriginalURL(r, f.PublicBaseURL))
		f.redirect(w, r, f.loginURL(r), http.StatusFound)
	}
}

// authenticate достаёт токен из куки и применяет политику доступа.
func (f *ForwardAuth) authenticate(r *http.Request) (*Claims, error) {
	cookie, err := r.Cookie(f.CookieName)
	if err != nil || cookie.Value == "" {
		return nil, ErrNoToken
	}
	claims, err := f.Verifier.Verify(cookie.Value)
	if err != nil {
		return nil, err
	}
	if f.RequireResident && !claims.IsResident && !f.isRoot(claims) {
		return nil, ErrNotResident
	}
	return claims, nil
}

// isRoot сообщает, что токен принадлежит администратору из конфигурации.
func (f *ForwardAuth) isRoot(c *Claims) bool {
	return f.RootAdmin != "" && c != nil && c.TelegramID == f.RootAdmin
}

// redirect отвечает редиректом браузеру и 401-м — программному клиенту.
//
// Без этого разделения XHR-запросы фронтенда Jellyfin или qBittorrent начнут
// молча следовать за редиректом на auth.akiba.space и падать на CORS,
// вместо понятного «сессия истекла».
func (f *ForwardAuth) redirect(w http.ResponseWriter, r *http.Request, target string, code int) {
	if !wantsHTML(r) {
		w.Header().Set("Cache-Control", "no-store")
		// Location всё равно отдаём: клиент может им воспользоваться сам.
		w.Header().Set("Location", target)
		http.Error(w, "требуется авторизация", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, code)
}

// loginURL строит ссылку на auth-service с возвратом на исходный адрес.
func (f *ForwardAuth) loginURL(r *http.Request) string {
	u := *f.AuthURL
	q := u.Query()
	q.Set("redirect_uri", f.withReturnBase(f.returnURL(r)))
	u.RawQuery = q.Encode()
	return u.String()
}

func (f *ForwardAuth) portalURL(reason string) string {
	u := *f.PublicBaseURL
	u.Path = "/"
	if reason != "" {
		q := u.Query()
		q.Set("error", reason)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// OriginalURL восстанавливает адрес, который резидент запросил у Traefik.
//
// В forwardAuth-запросе исходный запрос описан заголовками X-Forwarded-*,
// потому что сам HTTP-запрос идёт на /verify.
func OriginalURL(r *http.Request, fallback *url.URL) string {
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")

	if host == "" && fallback != nil {
		// Прямой заход мимо Traefik — например, при локальной отладке.
		u := *fallback
		u.Path = "/"
		return u.String()
	}
	// Схему проверяем, а не подставляем как есть: этот адрес уходит в
	// redirect_uri, и «X-Forwarded-Proto: javascript» с правильным хостом дал
	// бы ссылку javascript://inside.akiba.space/…, которая проверку «имя
	// заканчивается на .akiba.space» проходит. Всё, кроме двух известных
	// схем, заменяем на https: понижать протокол в ссылке возврата нельзя.
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto != "http" && proto != "https" {
		proto = "https"
	}
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return proto + "://" + host + uri
}

// wantsHTML отличает навигацию браузера от программного запроса.
func wantsHTML(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return false
	}
	// Fetch-метаданные современных браузеров: навигация помечена явно.
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	return strings.Contains(accept, "text/html")
}
