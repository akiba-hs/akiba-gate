package auth

import (
	"context"
	"errors"
	"net/http"
)

type ctxKey struct{}

// WithClaims кладёт разобранный токен в контекст запроса.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// FromContext достаёт токен, положенный Guard.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// Guard — middleware для собственных обработчиков шлюза.
//
// Принципиально: шлюз проверяет куку сам, а не верит заголовкам X-Akiba-*,
// которые проставил Traefik. Так одна ошибка в конфигурации прокси не
// превращается в дыру, и обработчики можно безопасно тестировать напрямую.
func (f *ForwardAuth) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		StripIdentityHeaders(r.Header)

		claims, err := f.authenticate(r)
		switch {
		case err == nil:
			// Заголовки идентичности здесь намеренно НЕ проставляются.
			// Обработчики шлюза берут разобранный токен из контекста, а
			// проставленные заголовки пришлось бы снимать в каждом прокси —
			// то есть шлюз изготавливал бы ровно то, от чего защищается,
			// и правильность зависела бы от памяти автора следующего прокси.
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		case errors.Is(err, ErrNotResident):
			f.redirect(w, r, f.portalURL("not_resident"), http.StatusFound)
		default:
			f.redirect(w, r, f.guardLoginURL(r), http.StatusFound)
		}
	})
}

// guardLoginURL строит адрес возврата для прямых (не forwardAuth) запросов:
// здесь исходный URL известен из самого запроса.
func (f *ForwardAuth) guardLoginURL(r *http.Request) string {
	host := RequestHost(r)
	if !f.allowedHost(host) {
		f.Log.Warn("возврат на посторонний хост отклонён", "forwarded_host", host)
		return f.portalURL("")
	}

	// Ориентируемся на X-Forwarded-Uri, а не на X-Forwarded-Host.
	//
	// Traefik ставит X-Forwarded-Host на любом проксируемом запросе, а
	// X-Forwarded-Uri — только внутри подзапроса forwardAuth. Проверяя хост,
	// мы никогда не попадали в эту ветку в проде: OriginalURL откатывался на
	// путь "/", и резидент после входа возвращался на портал вместо страницы,
	// куда шёл. Ради сохранения этого адреса ветка и написана.
	// Собираем адрес из самого запроса, если не хватает любого из двух
	// заголовков. С пустым X-Forwarded-Host получился бы адрес вида
	// "https:///jellyfin/web/", который auth-service отвергает с 400, не
	// оставляя следов ни у нас, ни у него.
	target := OriginalURL(r, nil)
	if r.Header.Get("X-Forwarded-Uri") == "" || r.Header.Get("X-Forwarded-Host") == "" {
		// Схему берём из запроса, а не из PUBLIC_BASE_URL. Traefik ходит к
		// шлюзу по http, поэтому r.TLS здесь всегда nil, и подстановка
		// схемы портала возвращала бы человека из локальной сети с http на
		// https — то есть на другой origin, где нет ни его localStorage
		// Jellyfin, ни совпадения Origin для qBittorrent.
		target = RequestScheme(r) + "://" + host + r.URL.RequestURI()
	}
	u := *f.AuthURL
	q := u.Query()
	q.Set("redirect_uri", f.withReturnBase(target))
	u.RawQuery = q.Encode()
	return u.String()
}
