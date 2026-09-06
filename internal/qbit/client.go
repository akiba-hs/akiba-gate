// Пакет qbit — клиент WebUI API qBittorrent и обратный прокси к нему.
//
// Аккаунт в qBittorrent один на всех резидентов (так решено в требованиях),
// поэтому шлюз держит одну служебную сессию и подставляет её в запросы уже
// авторизованных резидентов. Сам qBittorrent при этом остаётся закрытым
// паролем — в отличие от варианта с whitelist по подсети.
package qbit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client — минимальный клиент WebUI API.
type Client struct {
	base   *url.URL
	http   *http.Client
	user   string
	pass   string
	enable bool // false — режим bypass: логиниться не нужно

	mu            sync.Mutex
	sid           string
	lastErr       error
	lastErrAt     time.Time
	lastInvalidAt time.Time
	clock         func() time.Time
}

// loginBackoff — пауза после неудачного входа.
//
// qBittorrent банит клиента по IP после нескольких неудачных попыток (по
// умолчанию на час). Одна загрузка веб-интерфейса — это десятки запросов к
// API, и без паузы неверный пароль или перезапускающийся qBittorrent за
// секунды приводят к бану, который живёт кратно дольше самой неисправности.
const loginBackoff = 30 * time.Second

// loginTimeout ограничивает вход, отвязанный от контекста запроса.
// Без собственного срока такой вход висел бы до таймаута транспорта, держа
// мьютекс и все параллельные запросы за ним.
const loginTimeout = 15 * time.Second

// invalidateInterval — минимальный промежуток между сбросами сессии.
//
// Сброс делается на ответ 403, но 403 бывает и системным: разъехавшийся
// Referer, неверный Host, запрет в настройках. Веб-интерфейс опрашивает API
// несколько раз в секунду, поэтому без паузы шлюз начал бы логиниться на
// каждый запрос — бесконечно, успешно и совершенно незаметно.
const invalidateInterval = 5 * time.Second

// NewClient создаёт клиента.
//
// useSession=false — режим bypass: qBittorrent пускает подсеть шлюза без
// пароля, логиниться не нужно и не следует (лишние попытки входа приводят
// к бану по IP).
func NewClient(base *url.URL, httpClient *http.Client, user, pass string, useSession bool) *Client {
	return &Client{
		base:   base,
		http:   httpClient,
		user:   user,
		pass:   pass,
		enable: useSession && user != "",
		clock:  time.Now,
	}
}

// UsesSession сообщает, логинится ли шлюз в qBittorrent.
func (c *Client) UsesSession() bool { return c.enable }

// SID возвращает актуальный идентификатор сессии, логинясь при необходимости.
func (c *Client) SID(ctx context.Context) (string, error) {
	if !c.enable {
		return "", nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sid != "" {
		return c.sid, nil
	}
	// Пока держится пауза после неудачи, возвращаем прошлую ошибку, не
	// трогая сеть: повторные попытки только приближают бан.
	if c.lastErr != nil && c.clock().Sub(c.lastErrAt) < loginBackoff {
		return "", c.lastErr
	}

	// Логинимся в контексте, отвязанном от вызывающего запроса.
	//
	// Сессия здесь общая на всех, а контекст запроса умирает, как только
	// браузер ушёл со страницы или отменил один из десятков параллельных
	// подзапросов веб-интерфейса. С привязкой к нему одна такая отмена
	// записывалась бы в lastErr и на тридцать секунд оставляла без сессии
	// вообще всех — ровно та беда, от которой пауза и должна защищать.
	loginCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginTimeout)
	defer cancel()

	sid, err := c.loginLocked(loginCtx)
	if err != nil {
		// Отмену не запоминаем по той же причине: это не отказ qBittorrent,
		// и держать из-за неё паузу не за что.
		if !errors.Is(err, context.Canceled) {
			c.lastErr, c.lastErrAt = err, c.clock()
		}
		return "", err
	}
	c.lastErr = nil
	return sid, nil
}

// SetClock подменяет источник времени. Используется тестом паузы после
// неудачного входа: ждать реальные 30 секунд в тестах недопустимо.
func (c *Client) SetClock(now func() time.Time) {
	c.mu.Lock()
	c.clock = now
	c.mu.Unlock()
}

// Invalidate сбрасывает сессию: вызывается, когда qBittorrent ответил 403.
// Чаще, чем раз в invalidateInterval, сброс не выполняется.
func (c *Client) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if !c.lastInvalidAt.IsZero() && now.Sub(c.lastInvalidAt) < invalidateInterval {
		return
	}
	c.lastInvalidAt = now
	c.sid = ""
}

// invalidateUsed сбрасывает сессию, если она всё ещё та самая, которой только
// что отказали. Пауза здесь не действует.
//
// Пауза нужна прокси: веб-интерфейс шлёт запросы пачками, и на системный 403
// без неё шлюз логинился бы на каждый. Но внутренним запросам с их
// единственной повторной попыткой она вредна: пропущенный из-за паузы сброс
// означал бы повтор с той же мёртвой сессией и ошибку на исправном запросе.
// Проверка «сессия всё ещё та» не даёт выбросить новую, только что полученную
// соседней горутиной.
func (c *Client) invalidateUsed(sid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sid == sid {
		c.sid = ""
	}
}

func (c *Client) loginLocked(ctx context.Context) (string, error) {
	form := url.Values{"username": {c.user}, "password": {c.pass}}
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v2/auth/login",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("qbit: логин: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))

	if resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("qbit: логин отклонён (возможно, сработал бан по числу попыток): %s", strings.TrimSpace(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("qbit: логин вернул %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// qBittorrent отвечает 200 и телом "Fails." при неверном пароле.
	if strings.HasPrefix(strings.TrimSpace(string(body)), "Fails") {
		return "", fmt.Errorf("qbit: неверные учётные данные")
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == "SID" && ck.Value != "" {
			c.sid = ck.Value
			return c.sid, nil
		}
	}
	return "", fmt.Errorf("qbit: сервер не вернул cookie SID")
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := *c.base
	if i := strings.IndexByte(path, '?'); i >= 0 {
		u.Path, u.RawQuery = c.base.Path+path[:i], path[i+1:]
	} else {
		u.Path = c.base.Path + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("qbit: сборка запроса: %w", err)
	}
	// qBittorrent проверяет Referer/Origin как защиту от CSRF.
	origin := c.base.Scheme + "://" + c.base.Host
	req.Header.Set("Referer", origin)
	req.Header.Set("Origin", origin)
	return req, nil
}

// doAuthorized выполняет запрос с сессией и один раз перелогинивается на 403.
func (c *Client) doAuthorized(ctx context.Context, path string) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		sid, err := c.SID(ctx)
		if err != nil {
			return nil, err
		}
		req, err := c.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if sid != "" {
			req.AddCookie(&http.Cookie{Name: "SID", Value: sid})
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("qbit: запрос %s: %w", path, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("qbit: чтение ответа %s: %w", path, readErr)
		}
		if resp.StatusCode == http.StatusForbidden && attempt == 0 {
			c.invalidateUsed(sid) // сессия истекла — пробуем ещё раз
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("qbit: %s вернул %d", path, resp.StatusCode)
		}
		return body, nil
	}
	return nil, fmt.Errorf("qbit: не удалось авторизоваться для %s", path)
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	body, err := c.doAuthorized(ctx, path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("qbit: разбор ответа %s: %w", path, err)
	}
	return nil
}

// TorrentInfo — торрент из /api/v2/torrents/info.
//
// Полей у ответа qBittorrent несколько десятков; берём только те три, ради
// которых опрос и заведён. Лишние JSON игнорирует сам, а короткая структура
// не развалится, когда в очередной версии переименуют что-то соседнее.
type TorrentInfo struct {
	Hash     string  `json:"hash"`
	Name     string  `json:"name"`
	Progress float64 `json:"progress"` // 0..1, единица — загрузка завершена
}

// TorrentsInfo возвращает список торрентов вместе с прогрессом загрузки.
//
// Запрашиваем без фильтра по хешам намеренно. Фильтр пришлось бы передавать
// параметром hashes, а это сорок символов на торрент в адресе запроса: пара
// сотен отслеживаемых загрузок — и мы упираемся в предел длины строки
// запроса, который qBittorrent обрывает без внятной ошибки. Отбор по своему
// списку дешевле сделать у себя, по готовому ответу.
func (c *Client) TorrentsInfo(ctx context.Context) ([]TorrentInfo, error) {
	var out []TorrentInfo
	if err := c.getJSON(ctx, "/api/v2/torrents/info", &out); err != nil {
		return nil, err
	}
	return out, nil
}
