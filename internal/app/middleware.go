// Пакет app собирает HTTP-маршрутизацию шлюза из отдельных обработчиков.
package app

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// statusWriter запоминает код ответа для журнала доступа.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Unwrap нужен, чтобы http.ResponseController добрался до исходного writer'а
// (важно для потокового ответа Jellyfin и длинных запросов qBittorrent).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// accessLog пишет одну строку на запрос.
func accessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		log.Info("запрос",
			"method", r.Method,
			"host", r.Host,
			"path", r.URL.Path,
			"status", sw.status,
			"bytes", sw.bytes,
			// Числом, а не строкой "15ms": по строке нельзя построить ни
			// перцентиль, ни фильтр «дольше секунды».
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// recoverPanic не даёт панике в одном обработчике уронить весь шлюз.
func recoverPanic(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			// ErrAbortHandler — не сбой, а штатный сигнал «клиент ушёл»,
			// которым httputil.ReverseProxy обрывает ответ. Перехватывать её
			// нельзя: журнал заполнится фальшивыми паниками со стеками, а
			// попытка отдать 500 придётся на уже начатый ответ.
			if v == http.ErrAbortHandler {
				panic(v)
			}
			log.Error("паника в обработчике",
				"panic", v, "path", r.URL.Path, "stack", string(debug.Stack()))
			http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders добавляет заголовки, полезные на любом ответе шлюза.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		// X-Frame-Options не ставим глобально: Jellyfin и qBittorrent
		// проксируются как есть, и лишние ограничения ломают их интерфейс.
		// Собственные страницы шлюза закрываются от фрейминга поштучно —
		// см. OwnPageHeaders.
		next.ServeHTTP(w, r)
	})
}
