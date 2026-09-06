package jellyfin_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/jellyfin"
)

// seenRequest — то, что реально дошло до Jellyfin.
type seenRequest struct {
	Path   string
	Host   string
	Cookie string
	Akiba  string
	Fwd    string
}

// newProxyEnv поднимает фальшивый Jellyfin и прокси перед ним.
//
// Бэкенд отвечает эхом, а на "/" повторяет поведение настоящего Jellyfin:
// редирект на /web/ абсолютным путём, ничего не знающим о префиксе.
func newProxyEnv(t *testing.T) (*jellyfin.Proxy, *seenRequest) {
	t.Helper()
	seen := &seenRequest{}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Path = r.URL.RequestURI()
		seen.Host = r.Host
		seen.Cookie = r.Header.Get("Cookie")
		seen.Akiba = r.Header.Get(auth.HeaderUID)
		seen.Fwd = r.Header.Get("X-Forwarded-Host")
		if r.URL.Path == "/" {
			// Абсолютный Location: так отвечают части API Jellyfin.
			http.Redirect(w, r, "/web/", http.StatusFound)
			return
		}
		if r.URL.Path == "/relative" {
			// Относительный Location: именно так живой Jellyfin 10.11.11
			// отвечает на запрос корня.
			w.Header().Set("Location", "web/")
			w.WriteHeader(http.StatusFound)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/web/") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body>клиент Jellyfin</body></html>")
			return
		}
		_, _ = io.WriteString(w, "jellyfin: "+r.URL.Path)
	}))
	t.Cleanup(backend.Close)

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("разбор адреса заглушки: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return jellyfin.NewProxy("/jellyfin", target, log), seen
}

func TestProxyStripsPrefix(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	req := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/web/index.html", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код ответа = %d, ожидался 200", rec.Code)
	}
	if seen.Path != "/web/index.html" {
		t.Errorf("до Jellyfin дошёл путь %q, ожидался %q", seen.Path, "/web/index.html")
	}
}

func TestProxyKeepsQueryString(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	req := httptest.NewRequest(http.MethodGet,
		"http://inside.akiba.space/jellyfin/Items?userId=abc&limit=10", nil)
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if seen.Path != "/Items?userId=abc&limit=10" {
		t.Errorf("до Jellyfin дошёл путь %q, параметры потерялись", seen.Path)
	}
}

// Редирект без префикса увёл бы браузер на портал, а не в Jellyfin.
func TestProxyRestoresPrefixInLocation(t *testing.T) {
	proxy, _ := newProxyEnv(t)

	req := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if got := rec.Header().Get("Location"); got != "/jellyfin/web/" {
		t.Errorf("Location = %q, ожидался %q", got, "/jellyfin/web/")
	}
}

// Относительный Location трогать нельзя: браузер разрешит его относительно
// текущего адреса, то есть уже внутри префикса. Приписав префикс ещё раз,
// мы получили бы /jellyfin/jellyfin/web/. Живой Jellyfin 10.11.11 на запрос
// корня отвечает именно так — "Location: web/".
func TestProxyLeavesRelativeLocationAlone(t *testing.T) {
	proxy, _ := newProxyEnv(t)

	req := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/relative", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if got := rec.Header().Get("Location"); got != "web/" {
		t.Errorf("Location = %q, ожидался неизменный %q", got, "web/")
	}
}

// Без завершающего слэша относительные ссылки веб-клиента разрешились бы
// уровнем выше префикса.
func TestProxyRedirectsBarePrefixToSlash(t *testing.T) {
	proxy, _ := newProxyEnv(t)

	req := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("код ответа = %d, ожидался 301", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/jellyfin/" {
		t.Errorf("Location = %q, ожидался %q", got, "/jellyfin/")
	}
}

// В куке лежит JWT резидента: Jellyfin — посторонний сервис, ему её не видеть.
func TestProxyDropsCookies(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	req := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/web/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "jwt-residenta"})
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if seen.Cookie != "" {
		t.Errorf("до Jellyfin дошла кука %q, ожидалось, что её снимут", seen.Cookie)
	}
}

// Заголовки идентичности снимаются на каждой границе: одна забытая настройка
// прокси не должна давать возможность представиться чужим резидентом.
func TestProxyStripsIdentityHeaders(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	req := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/web/", nil)
	req.Header.Set(auth.HeaderUID, "tg777")
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if seen.Akiba != "" {
		t.Errorf("до Jellyfin дошёл заголовок идентичности %q", seen.Akiba)
	}
}

// Публичный хост нужен Jellyfin, чтобы строить абсолютные ссылки, ведущие
// обратно через шлюз, а не мимо него.
func TestProxyKeepsPublicHost(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	req := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/web/", nil)
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if seen.Host != "inside.akiba.space" {
		t.Errorf("Host у Jellyfin = %q, ожидался публичный inside.akiba.space", seen.Host)
	}
	if seen.Fwd != "inside.akiba.space" {
		t.Errorf("X-Forwarded-Host = %q, ожидался inside.akiba.space", seen.Fwd)
	}
}

// Недоступный Jellyfin — это 502 с внятным текстом, а не паника и не пустой
// ответ: страницу видит резидент, а не оператор.
func TestProxyReportsBackendFailure(t *testing.T) {
	target, err := url.Parse("http://127.0.0.1:9")
	if err != nil {
		t.Fatalf("разбор адреса: %v", err)
	}
	proxy := jellyfin.NewProxy("/jellyfin", target, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/web/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("код ответа = %d, ожидался 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Jellyfin недоступен") {
		t.Errorf("тело ответа = %q, ожидалось сообщение о недоступности", rec.Body.String())
	}
}

// Учётка в Jellyfin общая, поэтому изменять её резидент не должен: со
// страницы профиля он сменил бы пароль сразу всем.
func TestProxyBlocksUserModification(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	for _, path := range []string{
		"/jellyfin/Users/u1/Password",
		"/jellyfin/Users/u1",
		"/jellyfin/Users/New",
	} {
		r := httptest.NewRequest(http.MethodPost, "http://inside.akiba.space"+path, nil)
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s дал код %d, ожидался 403", path, w.Code)
		}
	}
	if seen.Path != "" {
		t.Errorf("запрос дошёл до Jellyfin: %q", seen.Path)
	}
}

// Ровно один POST под /Users/ обязан проходить — им завершается автовход.
func TestProxyAllowsQuickConnectExchange(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	r := httptest.NewRequest(http.MethodPost,
		"http://inside.akiba.space/jellyfin/Users/AuthenticateWithQuickConnect", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)

	if w.Code == http.StatusForbidden {
		t.Fatal("обмен секрета быстрого подключения заблокирован — автовход не работал бы")
	}
	if seen.Path != "/Users/AuthenticateWithQuickConnect" {
		t.Errorf("до Jellyfin дошёл путь %q", seen.Path)
	}
}

// Чтение под /Users/ нужно самому веб-клиенту и блокироваться не должно.
func TestProxyAllowsUserReads(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/Users/Me", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)

	if w.Code == http.StatusForbidden {
		t.Fatal("чтение профиля заблокировано")
	}
	if seen.Path != "/Users/Me" {
		t.Errorf("до Jellyfin дошёл путь %q", seen.Path)
	}
}

// Всё после «#» браузер серверу не отправляет, поэтому закрытые экраны
// Jellyfin ловятся только скриптом в самой странице.
func TestProxyInjectsHashGuardIntoWebPage(t *testing.T) {
	proxy, _ := newProxyEnv(t)

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/web/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)

	body := w.Body.String()
	for _, want := range []string{"hashchange", "login", "forgotpassword", "userprofile", "/sso/jellyfin"} {
		if !strings.Contains(body, want) {
			t.Errorf("в странице нет %q; сторож хэш-маршрутов не внедрён", want)
		}
	}
	// Длину тела обязательно пересчитать, иначе браузер обрежет страницу.
	if got := w.Header().Get("Content-Length"); got != "" && got != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %q при теле в %d байт", got, len(body))
	}
}

// В остальные ответы скрипт лезть не должен: это сломало бы JSON и бандлы.
func TestProxyDoesNotTouchOtherResponses(t *testing.T) {
	proxy, _ := newProxyEnv(t)

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/Items", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)

	if strings.Contains(w.Body.String(), "hashchange") {
		t.Fatal("сторож внедрён в ответ, который не является страницей веб-клиента")
	}
}

// Маршруты ASP.NET Core, на котором написан Jellyfin, регистр не различают:
// «/users/Password» попадает в тот же обработчик, что и «/Users/Password».
// Сравнение «как есть» закрывало бы одно написание из многих, а за ним стоит
// смена пароля общей учётки — то есть сразу всем.
func TestProxyBlocksUserModificationInAnyCase(t *testing.T) {
	proxy, seen := newProxyEnv(t)

	for _, path := range []string{
		"/jellyfin/users/Password",
		"/jellyfin/USERS/Password",
		"/jellyfin/Users/../Users/Password",
		"//jellyfin/Users/Password",
	} {
		r := httptest.NewRequest(http.MethodPost, "http://inside.akiba.space"+path, nil)
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s дал код %d, ожидался 403 (дошло до Jellyfin: %q)",
				path, w.Code, seen.Path)
		}
	}
}

// Страница больше ожидаемой раньше молча обрезалась и уходила браузеру с
// кодом 200 и подогнанной длиной — битый HTML без единой ошибки.
func TestProxyPassesOversizedIndexUnmodified(t *testing.T) {
	big := strings.Repeat("я", 700_000) // больше 1 МиБ в байтах
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>"+big+"</body></html>")
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	proxy := jellyfin.NewProxy("/jellyfin", target, slog.New(slog.NewTextHandler(io.Discard, nil)))

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/web/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.HasSuffix(body, "</body></html>") {
		t.Fatal("страница обрезана: браузер получил бы битый HTML с кодом 200")
	}
	if strings.Contains(body, "hashchange") {
		t.Error("в слишком большую страницу всё же внедрён сторож")
	}
}

// Сжатый ответ дописывать нельзя: получился бы мусор, который браузер не
// раскодирует, — и тоже с кодом 200.
func TestProxyLeavesCompressedIndexAlone(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "сжатые байты")
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	proxy := jellyfin.NewProxy("/jellyfin", target, slog.New(slog.NewTextHandler(io.Discard, nil)))

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space/jellyfin/web/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)

	if strings.Contains(w.Body.String(), "hashchange") {
		t.Fatal("сторож дописан к сжатому телу")
	}
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Error("заголовок сжатия снят, а тело осталось сжатым")
	}
}

// Установка плагина в Jellyfin — выполнение чужого кода на машине с
// медиатекой. Если общую учётку по ошибке завели администратором, эта
// проверка остаётся последней.
func TestProxyBlocksServerAdminPosts(t *testing.T) {
	cases := []string{
		"/jellyfin/Plugins/aaaaaaaa-0000-0000-0000-000000000000",
		"/jellyfin/Repositories",
		"/jellyfin/ScheduledTasks/Running/RefreshLibrary",
		"/jellyfin/System/Configuration",
		"/jellyfin/System/Restart",
		"/jellyfin/System/Shutdown",
		"/jellyfin/Startup/Configuration",
		// Регистр и двойные слэши маршруты ASP.NET Core не различают,
		// значит и проверка не должна.
		"/jellyfin/plugins/x",
		"//jellyfin/System/Restart",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			proxy, seen := newProxyEnv(t)
			r := httptest.NewRequest(http.MethodPost, target, nil)
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, r)

			if w.Code != http.StatusForbidden {
				t.Fatalf("код ответа %d, ожидался 403", w.Code)
			}
			if seen.Path != "" {
				t.Fatalf("запрос дошёл до Jellyfin: %s", seen.Path)
			}
		})
	}
}

// А обычная работа медиатеки закрываться не должна: /System/Ping веб-клиент
// зовёт сам, и запрет на него сломал бы интерфейс.
func TestProxyAllowsHarmlessSystemPosts(t *testing.T) {
	for _, target := range []string{
		"/jellyfin/System/Ping",
		"/jellyfin/Sessions/Capabilities/Full",
		"/jellyfin/Items/abc/PlaybackInfo",
	} {
		t.Run(target, func(t *testing.T) {
			proxy, _ := newProxyEnv(t)
			r := httptest.NewRequest(http.MethodPost, target, nil)
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, r)

			if w.Code == http.StatusForbidden {
				t.Fatalf("безобидный запрос закрыт: %s", target)
			}
		})
	}
}
