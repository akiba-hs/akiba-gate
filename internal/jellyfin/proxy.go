package jellyfin

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/upstream"
)

// Proxy отдаёт веб-интерфейс Jellyfin под публичным префиксом шлюза.
//
// Почему префикс снимает шлюз, а не Traefik. Автовход кладёт сессию в
// localStorage, а тот привязан к origin — значит страница автовхода и сам
// Jellyfin обязаны жить на одном origin. Отдать Jellyfin подпуть силами
// Traefik можно было бы только выставив в самом Jellyfin «Base URL»: сервер
// ожидал бы префикс в пути. Но тогда сменился бы и прямой адрес
// http://192.168.8.43:8096/, который решено оставить как есть. Поэтому
// префикс снимается здесь, а настройки Jellyfin не трогаются вовсе.
//
// Работает это потому, что веб-клиент Jellyfin ссылается на свои ресурсы
// относительными путями (проверено на 10.11.11: ни одного src/href,
// начинающегося со слэша), а адрес API берёт из сохранённых учётных данных —
// туда автовход кладёт публичный адрес вместе с префиксом.
type Proxy struct {
	basePath string
	target   *url.URL
	log      *slog.Logger
	rp       *httputil.ReverseProxy
}

// NewProxy собирает прокси. basePath — публичный префикс ("/jellyfin").
// ssoPath — адрес страницы автовхода: на неё уводит редирект со страниц
// логина самого Jellyfin.
const ssoPath = "/sso/jellyfin"

func NewProxy(basePath string, target *url.URL, log *slog.Logger) *Proxy {
	p := &Proxy{
		basePath: strings.TrimSuffix(basePath, "/"),
		target:   target,
		log:      log,
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.handleError,
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Без завершающего слэша относительные ссылки веб-клиента разрешались бы
	// на уровень выше префикса и попадали бы в портал.
	if r.URL.Path == p.basePath {
		http.Redirect(w, r, p.basePath+"/", http.StatusMovedPermanently)
		return
	}
	if reason, blocked := p.blocked(r); blocked {
		p.log.Warn("запрос к Jellyfin отклонён", "reason", reason,
			"method", r.Method, "path", r.URL.Path)
		http.Error(w, "этот запрос к Jellyfin закрыт", http.StatusForbidden)
		return
	}
	p.rp.ServeHTTP(w, r)
}

// allowedUsersPost — единственный POST к /Users/, который обязан проходить.
//
// Им завершается автовход: браузер меняет подтверждённый секрет быстрого
// подключения на токен. Всё остальное под /Users/ меняет общую учётку —
// пароль, профиль, настройки, — и это доступ, которого у резидента быть не
// должно: аккаунт один на всех.
const allowedUsersPost = "/Users/AuthenticateWithQuickConnect"

// adminOnlyPosts — пути, POST к которым меняет сам сервер, а не медиатеку.
//
// Прав на них у общей учётки быть не должно, и DEPLOY.md требует заводить её
// обычным пользователем. Но требование к настройке — не то же самое, что
// проверка: мастер установки Jellyfin делает первую учётку администратором, и
// переиспользовать её под резидентов — ошибка на одно движение. Цена такой
// ошибки здесь наибольшая в проекте: установка плагина в Jellyfin означает
// выполнение чужого кода на машине, где лежит вся медиатека.
//
// Поэтому запрет продублирован тут. Пути перечислены поимённо, а не префиксом
// «/system/»: под ним живёт и безобидный /System/Ping, который веб-клиент
// зовёт сам, и закрыть его значило бы сломать интерфейс.
var adminOnlyPosts = []string{
	"/plugins/",
	"/repositories",
	"/scheduledtasks/",
	"/system/configuration",
	"/system/restart",
	"/system/shutdown",
	"/startup/",
}

// blocked закрывает опасные запросы к Jellyfin.
//
// Сравнение идёт по нормализованному пути и без учёта регистра. Причина в
// том, что маршруты ASP.NET Core, на котором написан Jellyfin, регистр не
// различают: «/users/Password» попадает в тот же обработчик, что и
// «/Users/Password». Сравнение «как есть» закрывало бы ровно одно написание
// из многих, а за ним стоит смена пароля общей учётки — то есть всем сразу.
// Двойной слэш убирается по той же причине: «//Users/» бэкенд нормализует, а
// строковый префикс — нет.
func (p *Proxy) blocked(r *http.Request) (string, bool) {
	// Проверяются все методы, кроме безопасных: иначе защита обходится сменой
	// глагола — DELETE /Users/{id} и PUT/PATCH делают ровно то же, что POST,
	// и с правами общей учётки.
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "", false
	}
	// Нормализуем весь путь до снятия префикса: «//jellyfin/Users/…» иначе
	// не совпал бы с префиксом, остался бы неснятым и проверку миновал.
	// В маршрутизаторе такой запрос до сюда не доходит — ServeMux чистит путь
	// сам, — но прокси обязан быть верным и в одиночку.
	full := normalizePath(r.URL.Path)
	normalized := strings.TrimPrefix(full, strings.ToLower(p.basePath))
	if !strings.HasPrefix(normalized, "/") {
		normalized = full
	}
	if strings.HasPrefix(normalized, "/users/") &&
		normalized != strings.ToLower(allowedUsersPost) {
		return "изменение общей учётной записи", true
	}
	for _, prefix := range adminOnlyPosts {
		if strings.HasPrefix(normalized, prefix) {
			return "изменение настроек сервера", true
		}
	}
	return "", false
}

// normalizePath приводит путь к виду, в котором его увидит Jellyfin:
// схлопывает повторяющиеся слэши, убирает сегменты "." и ".." и опускает
// регистр.
func normalizePath(p string) string {
	cleaned := path.Clean("/" + strings.TrimPrefix(p, "/"))
	return strings.ToLower(cleaned)
}

// rewrite готовит исходящий запрос к Jellyfin.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	out := pr.Out
	pr.SetXForwarded()
	// SetXForwarded выводит протокол из r.In.TLS, а TLS у нас всегда снимает
	// Traefik — до шлюза запрос доходит по HTTP. Поэтому без этой строки
	// Jellyfin узнаёт, что резидент пришёл «по http», и, если у него включена
	// поддержка обратного прокси, строит абсолютные адреса с http:// — на
	// https-странице браузер их блокирует как смешанное содержимое.
	pr.Out.Header.Set("X-Forwarded-Proto", auth.RequestScheme(pr.In))

	out.URL.Scheme = p.target.Scheme
	out.URL.Host = p.target.Host
	out.URL.Path = p.target.Path + p.strip(pr.In.URL.Path)

	// В страницу веб-клиента подмешивается сторож хэш-маршрутов, а сделать
	// это можно только с несжатым ответом. Просим Jellyfin не сжимать именно
	// её: на остальных ответах сжатие остаётся как было.
	if isWebIndex(p.strip(pr.In.URL.Path)) {
		out.Header.Set("Accept-Encoding", "identity")
	}
	// out.Host намеренно оставлен публичным (это же делает passHostHeader в
	// Traefik): по нему Jellyfin строит часть абсолютных ссылок, и с
	// внутренним адресом они увели бы браузер мимо шлюза.

	// Кука браузера сюда попадать не должна: в ней лежит JWT резидента, а
	// Jellyfin для него — посторонний сервис. Собственных кук для входа
	// Jellyfin не использует, сессия живёт в localStorage.
	out.Header.Del("Cookie")
	auth.StripIdentityHeaders(out.Header)
}

// strip убирает публичный префикс, оставляя путь, понятный Jellyfin.
func (p *Proxy) strip(path string) string {
	if p.basePath == "" {
		return path
	}
	trimmed := strings.TrimPrefix(path, p.basePath)
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		return path
	}
	return trimmed
}

// modifyResponse возвращает префикс в редиректы Jellyfin.
//
// Сам Jellyfin о префиксе не знает и отвечает, например, «Location: /web/»
// на запрос корня. Без правки браузер ушёл бы на портал.
func (p *Proxy) modifyResponse(resp *http.Response) error {
	if loc := resp.Header.Get("Location"); loc != "" {
		resp.Header.Set("Location", upstream.Relocate(loc, p.basePath, p.target.Host))
	}
	return p.injectHashGuard(resp)
}

// isWebIndex распознаёт страницу-оболочку веб-клиента Jellyfin.
func isWebIndex(path string) bool {
	return path == "/web/" || path == "/web" || path == "/web/index.html"
}

// injectHashGuard дописывает в страницу веб-клиента сторож хэш-маршрутов.
//
// Почему это делается здесь, а не в Traefik и не в самом шлюзе по адресу.
// Всё, что идёт после «#», браузер серверу не отправляет вообще: и Traefik, и
// шлюз видят один и тот же запрос «GET /jellyfin/web/», каким бы ни был
// маршрут внутри. Закрыть #/login, #/forgotpassword и #/userprofile можно
// только в браузере — больше их никто не видит.
//
// Сторож нужен потому, что учётка в Jellyfin общая: со страницы профиля любой
// резидент сменил бы пароль всем сразу, а форма входа предлагает ввести чужой
// пароль вместо автовхода.
func (p *Proxy) injectHashGuard(resp *http.Response) error {
	if resp.Request == nil || !isWebIndex(p.strip(resp.Request.URL.Path)) {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return nil
	}
	// Сжатый ответ дописывать нельзя: получился бы мусор с кодом 200, который
	// браузер не раскодирует. Мы просим identity в rewrite, но проверяем, что
	// Jellyfin послушался.
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		p.log.Warn("страница веб-клиента пришла сжатой, сторож не внедрён",
			"encoding", enc)
		return nil
	}
	// Читаем на байт больше лимита, чтобы отличить «влезло» от «обрезано».
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexSize+1))
	if err != nil {
		return fmt.Errorf("jellyfin: чтение страницы веб-клиента: %w", err)
	}
	if len(body) > maxIndexSize {
		// Обрезанная страница с кодом 200 — худший исход: браузер получит
		// битый HTML и никакой ошибки. Лучше отдать её как есть, без сторожа.
		p.log.Error("страница веб-клиента больше ожидаемого, сторож не внедрён",
			"limit", maxIndexSize)
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
		return nil
	}
	if cerr := resp.Body.Close(); cerr != nil {
		return cerr
	}

	guard := []byte(strings.ReplaceAll(hashGuardScript, "{{SSO}}", ssoPath))
	if i := bytes.LastIndex(body, []byte("</body>")); i >= 0 {
		body = append(body[:i], append(guard, body[i:]...)...)
	} else {
		body = append(body, guard...)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	// Заголовки сжатия после правки тела соврали бы браузеру.
	resp.Header.Del("Content-Encoding")
	return nil
}

// maxIndexSize ограничивает страницу, которую готовы держать в памяти.
// index.html веб-клиента — единицы килобайт; всё, что сильно больше, значит,
// что мы читаем не то.
const maxIndexSize = 1 << 20

// hashGuardScript уводит с закрытых экранов Jellyfin на автовход.
const hashGuardScript = `
<script>
(function () {
  // Регулярное выражение повторяет адреса, которые Jellyfin использует для
  // входа, восстановления пароля и профиля, вместе с их параметрами.
  var closed = /^#\/(login|forgotpassword|forgotpasswordpin|userprofile|myprofile)(\.html)?(\?\S*)?$/;
  function check() {
    if (closed.test(location.hash)) {
      location.replace('{{SSO}}');
    }
  }
  window.addEventListener('hashchange', check);
  check();
})();
</script>
`

func (p *Proxy) handleError(w http.ResponseWriter, r *http.Request, err error) {
	p.log.Error("Jellyfin недоступен", "error", err, "path", r.URL.Path)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, "Jellyfin недоступен, попробуйте позже\n")
}
