// Пакет jellyfin выдаёт браузеру резидента готовую сессию Jellyfin, чтобы
// логин/пароль вводить не приходилось.
//
// По требованиям аккаунт в Jellyfin один общий на всех резидентов, поэтому
// шлюз держит одну сессию и переиспользует её токен. Разграничение доступа
// целиком на стороне шлюза: без валидного JWT до этой страницы не дойти.
package jellyfin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// clientName и deviceID попадают в список активных устройств Jellyfin —
// хочется, чтобы администратор понимал, что это за сессия.
const (
	clientName = "Akiba Gate"
	deviceName = "Akiba Gate"
	deviceID   = "akiba-gate"
	appVersion = "1.0.0"
)

// sessionTimeout ограничивает проверку и обновление служебной сессии.
//
// Контекст запроса для них не годится (см. Session), а совсем без срока
// висящий Jellyfin держал бы мьютекс и вместе с ним всех остальных.
const sessionTimeout = 20 * time.Second

// Session — служебная сессия шлюза в Jellyfin.
//
// Нужна ровно для одного: подтвердить код быстрого подключения от имени
// общей учётки. Сведений о сервере здесь нет намеренно — их берёт сам
// браузер на странице автовхода, и лишний запрос на каждый вход не нужен.
type Session struct {
	AccessToken string
	UserID      string
}

type authResponse struct {
	AccessToken string `json:"AccessToken"`
	User        struct {
		ID string `json:"Id"`
	} `json:"User"`
}

// Client — клиент Jellyfin с кэшем сессии.
type Client struct {
	base *url.URL
	http *http.Client
	user string
	pass string

	mu      sync.Mutex
	session *Session
}

// NewClient создаёт клиента для внутреннего адреса Jellyfin.
func NewClient(base *url.URL, httpClient *http.Client, user, pass string) *Client {
	return &Client{base: base, http: httpClient, user: user, pass: pass}
}

// Session возвращает действующую сессию, при необходимости логинясь заново.
//
// Кэш обязателен: без него каждый переход резидента создавал бы новое
// устройство в Jellyfin и замусоривал список сессий.
func (c *Client) Session(ctx context.Context) (Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Сессия здесь общая на всех, а контекст запроса умирает, как только
	// браузер ушёл со страницы. С привязкой к нему одна такая отмена
	// выбрасывала бы живую сессию и заводила в Jellyfin новое устройство
	// на ровном месте — а логин ниже всё равно упал бы по той же отмене.
	sessionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionTimeout)
	defer cancel()

	if c.session != nil {
		if ok, err := c.validateLocked(sessionCtx, *c.session); err == nil && ok {
			return *c.session, nil
		}
		c.session = nil
	}
	s, err := c.authenticateLocked(sessionCtx)
	if err != nil {
		return Session{}, err
	}
	c.session = &s
	return s, nil
}

// validateLocked проверяет, что токен ещё жив.
func (c *Client) validateLocked(ctx context.Context, s Session) (bool, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/Users/"+url.PathEscape(s.UserID), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", authHeader(s.AccessToken))
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("jellyfin: проверка сессии: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK, nil
}

func (c *Client) authenticateLocked(ctx context.Context) (Session, error) {
	payload, err := json.Marshal(map[string]string{"Username": c.user, "Pw": c.pass})
	if err != nil {
		return Session{}, fmt.Errorf("jellyfin: сборка запроса: %w", err)
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/Users/AuthenticateByName", bytes.NewReader(payload))
	if err != nil {
		return Session{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(""))

	resp, err := c.http.Do(req)
	if err != nil {
		return Session{}, fmt.Errorf("jellyfin: логин: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusUnauthorized {
		return Session{}, fmt.Errorf("jellyfin: неверные учётные данные общей учётки")
	}
	if resp.StatusCode != http.StatusOK {
		return Session{}, fmt.Errorf("jellyfin: логин вернул %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ar authResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return Session{}, fmt.Errorf("jellyfin: разбор ответа логина: %w", err)
	}
	if ar.AccessToken == "" || ar.User.ID == "" {
		return Session{}, fmt.Errorf("jellyfin: ответ логина без токена или учётной записи")
	}

	return Session{AccessToken: ar.AccessToken, UserID: ar.User.ID}, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := *c.base
	// Строку запроса отделяем явно: иначе "?" уедет в путь и будет
	// заэкранирован как %3F, а Jellyfin получит адрес, которого не знает.
	if i := strings.IndexByte(path, '?'); i >= 0 {
		u.Path, u.RawQuery = c.base.Path+path[:i], path[i+1:]
	} else {
		u.Path = c.base.Path + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("jellyfin: сборка запроса: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// authHeader формирует заголовок в формате, который ожидает Jellyfin.
func authHeader(token string) string {
	h := fmt.Sprintf(`MediaBrowser Client="%s", Device="%s", DeviceId="%s", Version="%s"`,
		clientName, deviceName, deviceID, appVersion)
	if token != "" {
		h += fmt.Sprintf(`, Token="%s"`, token)
	}
	return h
}
