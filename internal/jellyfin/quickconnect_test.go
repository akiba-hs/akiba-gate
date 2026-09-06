package jellyfin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/jellyfin"
)

// quickConnectBackend — заглушка Jellyfin: логин служебной учёткой и
// подтверждение кода. Поведение снято с живого 10.11.11: неизвестный код —
// 404, отсутствие токена — 401, успех — 200 с телом "true".
type quickConnectBackend struct {
	server     *httptest.Server
	goodCode   string
	authorized atomic.Int32
	gotCode    atomic.Value // string
	gotToken   atomic.Value // string
	logins     atomic.Int32
	expireOnce atomic.Bool // один раз ответить 401, изображая истёкший токен
}

func newQuickConnectBackend(t *testing.T, goodCode string) *quickConnectBackend {
	t.Helper()
	b := &quickConnectBackend{goodCode: goodCode}
	b.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/Users/AuthenticateByName":
			b.logins.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"AccessToken":"tok-`+
				time.Now().Format("150405.000000000")+`","ServerId":"srv","User":{"Id":"u1","Name":"admin"}}`)
		case r.URL.Path == "/Users/AuthenticateWithQuickConnect":
			if b.authorized.Load() == 0 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w,
				`{"AccessToken":"qc-token","ServerId":"srv","User":{"Id":"u1","Name":"admin"}}`)
		case strings.HasPrefix(r.URL.Path, "/Users/"):
			w.WriteHeader(http.StatusOK) // проверка живости сессии
		case r.URL.Path == "/System/Info/Public":
			_, _ = io.WriteString(w, `{"Id":"srv","ServerName":"akiba","Version":"10.11.11"}`)
		case r.URL.Path == "/QuickConnect/Enabled":
			_, _ = io.WriteString(w, "true")
		case r.URL.Path == "/QuickConnect/Initiate":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// Живой Jellyfin требует заголовок клиента и без него отвечает
			// ошибкой — заглушка ведёт себя так же.
			if !strings.HasPrefix(r.Header.Get("Authorization"), "MediaBrowser ") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `{"Authenticated":false,"Secret":"SECRET-1","Code":"`+
				b.goodCode+`"}`)
		case r.URL.Path == "/QuickConnect/Authorize":
			token := ""
			if h := r.Header.Get("Authorization"); strings.Contains(h, `Token="`) {
				token = h[strings.Index(h, `Token="`)+7:]
				token = strings.TrimSuffix(token, `"`)
			}
			b.gotToken.Store(token)
			b.gotCode.Store(r.URL.Query().Get("code"))
			if b.expireOnce.CompareAndSwap(true, false) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if token == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("code") != b.goodCode {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, "Error processing request.")
				return
			}
			b.authorized.Add(1)
			_, _ = io.WriteString(w, "true")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(b.server.Close)
	return b
}

func (b *quickConnectBackend) client(t *testing.T) *jellyfin.Client {
	t.Helper()
	u, err := url.Parse(b.server.URL)
	if err != nil {
		t.Fatalf("разбор адреса заглушки: %v", err)
	}
	return jellyfin.NewClient(u, &http.Client{Timeout: 5 * time.Second}, "admin", "pass")
}

func TestAuthorizeQuickConnectApprovesCode(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	c := b.client(t)

	if err := c.AuthorizeQuickConnect(context.Background(), "705558"); err != nil {
		t.Fatalf("подтверждение кода: %v", err)
	}
	if b.authorized.Load() != 1 {
		t.Fatalf("Jellyfin не получил подтверждение, вызовов: %d", b.authorized.Load())
	}
	if got, _ := b.gotToken.Load().(string); got == "" {
		t.Error("код подтверждали без служебного токена — Jellyfin ответил бы 401")
	}
}

// Неизвестный или истёкший код — обычное дело, а не сбой: человек ошибся
// цифрой либо слишком долго думал. Отличать его от поломки Jellyfin нужно,
// чтобы показать понятный текст.
func TestAuthorizeQuickConnectReportsUnknownCode(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	c := b.client(t)

	err := c.AuthorizeQuickConnect(context.Background(), "000000")
	if !errors.Is(err, jellyfin.ErrQuickConnectCodeUnknown) {
		t.Fatalf("ошибка = %v, ожидалась ErrQuickConnectCodeUnknown", err)
	}
}

// Служебный токен живёт не вечно. Без повторной попытки резидент получал бы
// «код не подошёл» на совершенно верный код — и никакого способа понять, что
// дело в сессии шлюза.
func TestAuthorizeQuickConnectRetriesOnExpiredSession(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	b.expireOnce.Store(true)
	c := b.client(t)

	if err := c.AuthorizeQuickConnect(context.Background(), "705558"); err != nil {
		t.Fatalf("подтверждение кода после истёкшей сессии: %v", err)
	}
	if b.logins.Load() < 2 {
		t.Errorf("шлюз не перелогинился: входов %d, ожидалось не меньше 2", b.logins.Load())
	}
}

// newQuickConnectHandler собирает обработчик со своим именем хоста.
func newQuickConnectHandler(t *testing.T, b *quickConnectBackend) http.Handler {
	t.Helper()
	base, _ := url.Parse("http://inside.akiba.space:8080")
	return &jellyfin.QuickConnectHandler{
		Client:   b.client(t),
		BasePath: "/jellyfin",
		Hosts:    auth.HostPolicy{Base: base},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func postCode(t *testing.T, h http.Handler, code string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"code": {code}}
	r := httptest.NewRequest(http.MethodPost, "http://inside.akiba.space:8080"+jellyfin.QuickConnectPath,
		strings.NewReader(form.Encode()))
	r.Host = "inside.akiba.space:8080"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestQuickConnectHandlerShowsForm(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newQuickConnectHandler(t, b)

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space:8080"+jellyfin.QuickConnectPath, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("код %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `name="code"`) {
		t.Error("на странице нет поля для кода")
	}
	if b.authorized.Load() != 0 {
		t.Error("GET не должен ничего подтверждать")
	}
}

// Люди переносят код с экрана и добавляют пробелы или дефис.
func TestQuickConnectHandlerNormalisesCode(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newQuickConnectHandler(t, b)

	w := postCode(t, h, " 705-558 ", map[string]string{"Origin": "http://inside.akiba.space:8080"})

	if b.authorized.Load() != 1 {
		t.Fatalf("код не подтверждён; в Jellyfin ушло %q", b.gotCode.Load())
	}
	if !strings.Contains(w.Body.String(), "Код подтверждён") {
		t.Errorf("нет сообщения об успехе; тело: %q", w.Body.String())
	}
}

func TestQuickConnectHandlerReportsWrongCode(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newQuickConnectHandler(t, b)

	w := postCode(t, h, "111111", map[string]string{"Origin": "http://inside.akiba.space:8080"})

	body := w.Body.String()
	if !strings.Contains(body, "не найден") {
		t.Errorf("нет понятного сообщения о неверном коде; тело: %q", body)
	}
	if strings.Contains(body, "Код подтверждён") {
		t.Error("неверный код показан как успешный")
	}
}

func TestQuickConnectHandlerRejectsEmptyCode(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newQuickConnectHandler(t, b)

	w := postCode(t, h, "   ", map[string]string{"Origin": "http://inside.akiba.space:8080"})

	if b.authorized.Load() != 0 {
		t.Error("пустой код ушёл в Jellyfin")
	}
	if !strings.Contains(w.Body.String(), "Введите код") {
		t.Errorf("нет подсказки о пустом коде; тело: %q", w.Body.String())
	}
}

// Подтверждение кода выдаёт рабочую сессию Jellyfin, поэтому форму нельзя
// отправить с чужой страницы: иначе достаточно заманить вошедшего резидента
// на подготовленный сайт, чтобы получить доступ к медиатеке.
func TestQuickConnectHandlerRejectsCrossSite(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newQuickConnectHandler(t, b)

	w := postCode(t, h, "705558", map[string]string{"Origin": "https://evil.example"})

	if w.Code != http.StatusForbidden {
		t.Fatalf("код %d, ожидался 403", w.Code)
	}
	if b.authorized.Load() != 0 {
		t.Error("межсайтовый запрос всё же подтвердил код")
	}
}

func TestQuickConnectHandlerRejectsCrossSiteByFetchMetadata(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newQuickConnectHandler(t, b)

	w := postCode(t, h, "705558", map[string]string{"Sec-Fetch-Site": "cross-site"})

	if w.Code != http.StatusForbidden {
		t.Fatalf("код %d, ожидался 403", w.Code)
	}
	if b.authorized.Load() != 0 {
		t.Error("межсайтовый запрос всё же подтвердил код")
	}
}

// newApproveAPI собирает JSON-эндпоинт подтверждения кода.
func newApproveAPI(t *testing.T, b *quickConnectBackend) http.Handler {
	t.Helper()
	base, _ := url.Parse("http://inside.akiba.space:8080")
	return &jellyfin.QuickConnectAPI{
		Client: b.client(t),
		Hosts:  auth.HostPolicy{Base: base},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func postJSON(t *testing.T, h http.Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost,
		"http://inside.akiba.space:8080"+jellyfin.QuickConnectApprovePath, strings.NewReader(body))
	r.Host = "inside.akiba.space:8080"
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestApproveAPIConfirmsCode(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newApproveAPI(t, b)

	w := postJSON(t, h, `{"code":"705558"}`, map[string]string{"Origin": "http://inside.akiba.space:8080"})

	if w.Code != http.StatusOK {
		t.Fatalf("код %d, тело %q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Errorf("тело = %q", w.Body.String())
	}
	if b.authorized.Load() != 1 {
		t.Error("код не подтверждён в Jellyfin")
	}
}

// Страница автовхода показывает текст ошибки как есть, поэтому он должен
// быть человеческим, а не «500».
func TestApproveAPIExplainsUnknownCode(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newApproveAPI(t, b)

	w := postJSON(t, h, `{"code":"000000"}`, map[string]string{"Origin": "http://inside.akiba.space:8080"})

	if w.Code != http.StatusConflict {
		t.Fatalf("код %d, ожидался 409", w.Code)
	}
	if !strings.Contains(w.Body.String(), "истечь") {
		t.Errorf("нет понятного объяснения; тело: %q", w.Body.String())
	}
}

func TestApproveAPIRejectsCrossSite(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newApproveAPI(t, b)

	w := postJSON(t, h, `{"code":"705558"}`, map[string]string{"Origin": "https://evil.example"})

	if w.Code != http.StatusForbidden {
		t.Fatalf("код %d, ожидался 403", w.Code)
	}
	if b.authorized.Load() != 0 {
		t.Error("межсайтовый запрос всё же подтвердил код")
	}
}

func TestApproveAPIRejectsGarbage(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newApproveAPI(t, b)

	for _, body := range []string{`не json`, `{"code":""}`, `{"code":"12345678901234567"}`} {
		w := postJSON(t, h, body, map[string]string{"Origin": "http://inside.akiba.space:8080"})
		if w.Code != http.StatusBadRequest {
			t.Errorf("тело %q дало код %d, ожидался 400", body, w.Code)
		}
	}
	if b.authorized.Load() != 0 {
		t.Error("мусор ушёл в Jellyfin")
	}
}

// То же правило для подтверждения кода Jellyfin: "null" — неизвестный
// источник, а не свой.
func TestApproveAPIRejectsNullOrigin(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	h := newApproveAPI(t, b)

	w := postJSON(t, h, `{"code":"705558"}`, map[string]string{"Origin": "null"})

	if w.Code != http.StatusForbidden {
		t.Fatalf("код %d, ожидался 403", w.Code)
	}
	if b.authorized.Load() != 0 {
		t.Error("код подтверждён по запросу с неизвестным источником")
	}
}

// Серверная половина автовхода целиком: браузер получает код через прокси
// шлюза, шлюз подтверждает его служебной учёткой, браузер обменивает секрет
// на токен — тоже через прокси. Сам JavaScript страницы тестом не покрыт, но
// всё, что может тихо разъехаться в Go, проверяется здесь.
func TestQuickConnectFlowThroughProxy(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	target, _ := url.Parse(b.server.URL)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	base, _ := url.Parse("http://inside.akiba.space:8080")
	hosts := auth.HostPolicy{Base: base}

	proxy := jellyfin.NewProxy("/jellyfin", target, log)
	approve := &jellyfin.QuickConnectAPI{Client: b.client(t), Hosts: hosts, Log: log}

	clientHeader := `MediaBrowser Client="Jellyfin Web", Device="Browser", DeviceId="d1", Version="10.11.11"`

	// 1. Браузер запрашивает код через прокси.
	r := httptest.NewRequest(http.MethodPost, "http://inside.akiba.space:8080/jellyfin/QuickConnect/Initiate", nil)
	r.Host = "inside.akiba.space:8080"
	r.Header.Set("Authorization", clientHeader)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("Initiate через прокси: код %d, тело %q", w.Code, w.Body.String())
	}
	var qc struct{ Secret, Code string }
	if err := json.Unmarshal(w.Body.Bytes(), &qc); err != nil {
		t.Fatalf("разбор ответа Initiate: %v", err)
	}
	if qc.Code == "" || qc.Secret == "" {
		t.Fatalf("Initiate вернул %+v", qc)
	}

	// 2. Шлюз подтверждает код.
	w = postJSON(t, approve, `{"code":"`+qc.Code+`"}`,
		map[string]string{"Origin": "http://inside.akiba.space:8080"})
	if w.Code != http.StatusOK {
		t.Fatalf("подтверждение: код %d, тело %q", w.Code, w.Body.String())
	}

	// 3. Браузер меняет секрет на токен — тоже через прокси.
	r = httptest.NewRequest(http.MethodPost,
		"http://inside.akiba.space:8080/jellyfin/Users/AuthenticateWithQuickConnect",
		strings.NewReader(`{"Secret":"`+qc.Secret+`"}`))
	r.Host = "inside.akiba.space:8080"
	r.Header.Set("Authorization", clientHeader)
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("обмен секрета: код %d, тело %q", w.Code, w.Body.String())
	}
	var res struct{ AccessToken string }
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("разбор ответа обмена: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("обмен прошёл без токена")
	}
}

// Без подтверждения обмен секрета не проходит: иначе достаточно было бы
// вызвать Initiate, чтобы получить доступ к медиатеке без всякой авторизации.
func TestQuickConnectExchangeFailsWithoutApproval(t *testing.T) {
	b := newQuickConnectBackend(t, "705558")
	target, _ := url.Parse(b.server.URL)
	proxy := jellyfin.NewProxy("/jellyfin", target, slog.New(slog.NewTextHandler(io.Discard, nil)))

	r := httptest.NewRequest(http.MethodPost,
		"http://inside.akiba.space:8080/jellyfin/Users/AuthenticateWithQuickConnect",
		strings.NewReader(`{"Secret":"SECRET-1"}`))
	r.Host = "inside.akiba.space:8080"
	r.Header.Set("Authorization", `MediaBrowser Client="Jellyfin Web", Device="Browser", DeviceId="d1", Version="10.11.11"`)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("код %d, ожидался 401 без подтверждения", w.Code)
	}
}
