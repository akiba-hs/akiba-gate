package jellyfin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/akiba-hs/akiba-gate/internal/auth"
)

// Ошибки подтверждения кода, которые имеет смысл показать человеку.
var (
	// ErrQuickConnectCodeUnknown — код не найден: опечатка либо истёк срок.
	// Jellyfin держит запрос недолго и отвечает на такой код 404.
	ErrQuickConnectCodeUnknown = errors.New("jellyfin: код не найден или уже истёк")
	// ErrQuickConnectDisabled — быстрое подключение выключено в настройках.
	ErrQuickConnectDisabled = errors.New("jellyfin: быстрое подключение выключено на сервере")
)

// AuthorizeQuickConnect подтверждает код, который Jellyfin показал резиденту.
//
// Почему это стоит отдельно от автовхода через localStorage. Здесь сессию
// заводит себе сам веб-клиент Jellyfin — штатным для него способом, — а шлюз
// только подтверждает запрос служебной учёткой. Поэтому способ не зависит ни
// от формата хранилища, ни от версии клиента: ломаться нечему.
//
// Цена — одно действие резидента: код нужно перенести с экрана Jellyfin.
// Автоматически его не узнать: у Jellyfin нет способа перечислить ожидающие
// запросы, и это не упущение, а защита — иначе подтверждать можно было бы
// чужие.
func (c *Client) AuthorizeQuickConnect(ctx context.Context, code string) error {
	// Одна повторная попытка: служебный токен мог истечь, и тогда Jellyfin
	// ответит 401 на совершенно верный код.
	for attempt := 0; attempt < 2; attempt++ {
		session, err := c.Session(ctx)
		if err != nil {
			return err
		}
		req, err := c.newRequest(ctx, http.MethodPost,
			"/QuickConnect/Authorize?code="+url.QueryEscape(code), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", authHeader(session.AccessToken))

		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("jellyfin: подтверждение кода: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// Jellyfin отвечает телом "true" или "false": false означает,
			// что подтвердить не удалось, хотя запрос он понял.
			if strings.TrimSpace(string(body)) == "false" {
				return ErrQuickConnectCodeUnknown
			}
			return nil
		case http.StatusNotFound:
			return ErrQuickConnectCodeUnknown
		case http.StatusForbidden:
			return ErrQuickConnectDisabled
		case http.StatusUnauthorized:
			c.invalidate()
			continue
		default:
			return fmt.Errorf("jellyfin: подтверждение кода вернуло %d: %s",
				resp.StatusCode, strings.TrimSpace(string(body)))
		}
	}
	return fmt.Errorf("jellyfin: не удалось авторизоваться для подтверждения кода")
}

// invalidate сбрасывает служебную сессию: следующий вызов войдёт заново.
func (c *Client) invalidate() {
	c.mu.Lock()
	c.session = nil
	c.mu.Unlock()
}

// QuickConnectPath — адрес страницы подтверждения кода.
const QuickConnectPath = "/sso/jellyfin/connect"

// QuickConnectHandler принимает код быстрого подключения и подтверждает его.
type QuickConnectHandler struct {
	Client   *Client
	BasePath string // публичный префикс Jellyfin, чтобы дать ссылку на вход
	// Hosts нужен для проверки происхождения формы: подтверждение кода
	// заводит рабочую сессию Jellyfin, поэтому отправить эту форму с чужой
	// страницы быть не должно.
	Hosts auth.HostPolicy
	// Attempts ограничивает частоту подтверждений. Может быть nil — тогда
	// ограничения нет.
	Attempts *AttemptLimiter
	Log      *slog.Logger
}

type quickConnectView struct {
	LoginURL string
	Code     string
	Success  bool
	Error    string
}

func (h *QuickConnectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vm := quickConnectView{LoginURL: h.BasePath + "/web/#/login.html"}

	if r.Method == http.MethodPost {
		if reason, blocked := crossSite(h.Hosts, r); blocked {
			h.Log.Warn("подтверждение кода Jellyfin отклонено как межсайтовое", "reason", reason)
			http.Error(w, "межсайтовый запрос отклонён", http.StatusForbidden)
			return
		}
		vm = h.authorize(r, vm)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, private")
	auth.OwnPageHeaders(w.Header())
	if err := quickConnectTemplate.Execute(w, vm); err != nil {
		h.Log.Error("не удалось отрендерить страницу быстрого подключения", "error", err)
	}
}

// authorize разбирает форму и подтверждает код.
func (h *QuickConnectHandler) authorize(r *http.Request, vm quickConnectView) quickConnectView {
	if err := r.ParseForm(); err != nil {
		vm.Error = "не удалось разобрать форму"
		return vm
	}
	code := digitsOnly(r.PostFormValue("code"))
	vm.Code = code
	switch {
	case code == "":
		vm.Error = "Введите код — его показывает Jellyfin после нажатия «Быстрое подключение»."
		return vm
	// Длину не проверяем жёстко: её задаёт сервер, и сегодня это шесть цифр.
	// Ограничиваем только сверху, чтобы не гонять в Jellyfin мусор.
	case len(code) > 16:
		vm.Error = "Код слишком длинный — в нём должны быть только цифры с экрана Jellyfin."
		return vm
	}

	if !h.Attempts.Allow(actor(r)) {
		h.Log.Warn("подтверждение кода Jellyfin отклонено: слишком часто",
			"user", actor(r))
		vm.Error = "Слишком много попыток. Подождите минуту и попробуйте снова."
		return vm
	}

	err := h.Client.AuthorizeQuickConnect(r.Context(), code)
	switch {
	case err == nil:
		h.Log.Info("код быстрого подключения Jellyfin подтверждён", "user", actor(r))
		vm.Success = true
	case errors.Is(err, ErrQuickConnectCodeUnknown):
		vm.Error = "Код не найден или уже истёк. Обновите страницу Jellyfin и попробуйте снова."
	case errors.Is(err, ErrQuickConnectDisabled):
		vm.Error = "Быстрое подключение выключено в настройках Jellyfin."
	default:
		h.Log.Error("не удалось подтвердить код быстрого подключения", "error", err)
		vm.Error = "Jellyfin недоступен, попробуйте позже."
	}
	return vm
}

// actor — кто подтверждает код. По нему же считаются попытки.
func actor(r *http.Request) string {
	if claims, ok := auth.FromContext(r.Context()); ok {
		return claims.UID()
	}
	return ""
}

// digitsOnly оставляет от введённого только цифры: люди переносят код с
// экрана и добавляют пробелы и дефисы.
func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var quickConnectTemplate = template.Must(template.New("jellyfin-quick-connect").Parse(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вход в Jellyfin по коду</title>
<style>
  body { margin:0; background:#16181d; color:#e8e6e3; font:16px/1.5 system-ui, sans-serif;
         display:flex; min-height:100vh; align-items:center; justify-content:center; padding:20px; }
  .card { width:100%; max-width:460px; background:#1f2229; border:1px solid #2e3440;
          border-radius:14px; padding:26px; }
  h1 { font-size:1.3rem; margin:0 0 14px; }
  ol { padding-left:20px; margin:0 0 20px; }
  li { margin-bottom:6px; }
  input { width:100%; box-sizing:border-box; font-size:1.6rem; letter-spacing:.28em;
          text-align:center; padding:12px; border-radius:10px; border:1px solid #3a4150;
          background:#14161a; color:#e8e6e3; margin-bottom:14px; }
  button, .btn { display:block; width:100%; box-sizing:border-box; text-align:center;
          padding:12px; border:0; border-radius:10px; background:#b9293b; color:#fff;
          font-size:1rem; font-weight:600; cursor:pointer; text-decoration:none; }
  .muted { color:#9aa0ab; font-size:.9rem; }
  .warn { border-color:#d08a1e; }
  .msg { padding:10px 12px; border-radius:10px; margin-bottom:16px; }
  .msg.err { background:#3a1f24; border:1px solid #b9293b; }
  .msg.ok { background:#1e3326; border:1px solid #3f8f5a; }
  a { color:#e8a0ab; }
</style>
</head>
<body>
<main class="card{{if .Error}} warn{{end}}">
  <h1>Вход в Jellyfin по коду</h1>

  {{if .Success}}
    <div class="msg ok">Код подтверждён. Вернитесь на вкладку Jellyfin — вход
      завершится сам через несколько секунд.</div>
    <a class="btn" href="{{.LoginURL}}">Открыть Jellyfin</a>
  {{else}}
    {{if .Error}}<div class="msg err">{{.Error}}</div>{{end}}
    <ol>
      <li>Откройте <a href="{{.LoginURL}}" target="_blank" rel="noopener">Jellyfin</a>
          и нажмите «Быстрое подключение».</li>
      <li>Перенесите показанный код сюда.</li>
    </ol>
    <form method="post">
      <input name="code" inputmode="numeric" autocomplete="off" autofocus
             placeholder="000000" value="{{.Code}}">
      <button type="submit">Подтвердить</button>
    </form>
    <p class="muted" style="margin-top:16px">Вводите только тот код, который
      видите на своём экране. Чужой код, присланный со стороны, откроет
      отправителю доступ к медиатеке.</p>
  {{end}}
</main>
</body>
</html>
`))

// QuickConnectApprovePath — адрес, по которому страница автовхода отдаёт
// шлюзу код на подтверждение.
const QuickConnectApprovePath = "/sso/jellyfin/approve"

// QuickConnectAPI подтверждает код быстрого подключения по запросу из
// браузера. Отличается от QuickConnectHandler только форматом: там форма и
// HTML, здесь JSON для страницы автовхода.
type QuickConnectAPI struct {
	Client *Client
	Hosts  auth.HostPolicy
	// Attempts ограничивает частоту подтверждений. Экземпляр общий с формой:
	// иначе норму можно было бы удвоить, чередуя форму и этот адрес.
	Attempts *AttemptLimiter
	Log      *slog.Logger
}

type approveRequest struct {
	Code string `json:"code"`
}

type approveResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (h *QuickConnectAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	// Подтверждение кода выдаёт рабочую сессию Jellyfin, поэтому запрос с
	// чужой страницы недопустим — иначе достаточно заманить вошедшего
	// резидента на подготовленный сайт.
	if reason, blocked := crossSite(h.Hosts, r); blocked {
		h.Log.Warn("подтверждение кода Jellyfin отклонено как межсайтовое", "reason", reason)
		writeApprove(w, http.StatusForbidden, approveResponse{Error: "межсайтовый запрос отклонён"})
		return
	}

	var req approveRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		writeApprove(w, http.StatusBadRequest, approveResponse{Error: "не удалось разобрать запрос"})
		return
	}
	code := digitsOnly(req.Code)
	if code == "" || len(code) > 16 {
		writeApprove(w, http.StatusBadRequest, approveResponse{Error: "некорректный код"})
		return
	}

	if !h.Attempts.Allow(actor(r)) {
		h.Log.Warn("подтверждение кода Jellyfin отклонено: слишком часто",
			"user", actor(r))
		writeApprove(w, http.StatusTooManyRequests,
			approveResponse{Error: "слишком много попыток, подождите минуту"})
		return
	}

	err := h.Client.AuthorizeQuickConnect(r.Context(), code)
	switch {
	case err == nil:
		h.Log.Info("код быстрого подключения Jellyfin подтверждён", "user", actor(r))
		writeApprove(w, http.StatusOK, approveResponse{OK: true})
	case errors.Is(err, ErrQuickConnectCodeUnknown):
		writeApprove(w, http.StatusConflict,
			approveResponse{Error: "Jellyfin не признал код: он мог истечь, попробуйте ещё раз"})
	case errors.Is(err, ErrQuickConnectDisabled):
		writeApprove(w, http.StatusConflict,
			approveResponse{Error: "быстрое подключение выключено в настройках Jellyfin"})
	default:
		h.Log.Error("не удалось подтвердить код быстрого подключения", "error", err)
		writeApprove(w, http.StatusBadGateway,
			approveResponse{Error: "Jellyfin недоступен, попробуйте позже"})
	}
}

func writeApprove(w http.ResponseWriter, status int, body approveResponse) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// crossSite решает, пришёл ли запрос с чужой страницы. Общая для формы и
// для JSON-эндпоинта: правило одно, и расходиться им нельзя.
func crossSite(hosts auth.HostPolicy, r *http.Request) (string, bool) {
	self, _ := hosts.Origin(r)
	// "null" — неизвестный источник, а не свой: см. пояснение в qbit.Proxy.
	if origin := r.Header.Get("Origin"); origin != "" && origin != self {
		return "origin " + origin, true
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" || site == "same-site" {
		return "sec-fetch-site " + site, true
	}
	return "", false
}
