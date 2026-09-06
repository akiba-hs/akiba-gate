package nextcloud_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/nextcloud"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const testSecret = "секрет-длиной-больше-тридцати-двух-символов"

func newStart(t *testing.T, codes *nextcloud.Codes, bindIP bool) *nextcloud.StartHandler {
	t.Helper()
	pub, err := url.Parse("https://nextcloud.akiba.space")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return &nextcloud.StartHandler{
		Codes:     codes,
		PublicURL: pub,
		SSOPath:   "/index.php/apps/akibasso/login",
		BindIP:    bindIP,
		Log:       quiet(),
	}
}

// authorized кладёт в запрос разобранный токен — так же, как это делает Guard.
func authorized(r *http.Request) *http.Request {
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{
		TelegramID: "270369579", Username: "ilvesbogdan",
		FirstName: "Bogdan", LastName: "Ilves", IsResident: true,
	}))
}

func TestStartRedirectsWithCode(t *testing.T) {
	codes := nextcloud.NewCodes()
	h := newStart(t, codes, false)

	r := authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("код ответа %d, ожидался 303", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location не разбирается: %v", err)
	}
	if loc.Host != "nextcloud.akiba.space" {
		t.Fatalf("редирект на %q", loc.Host)
	}
	if loc.Path != "/index.php/apps/akibasso/login" {
		t.Fatalf("путь %q", loc.Path)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("в адресе нет кода")
	}
	// Код обязан быть настоящим: обмен должен пройти.
	id, err := codes.Redeem(code, "", "")
	if err != nil {
		t.Fatalf("выданный код не обменивается: %v", err)
	}
	if id.UID != "tg270369579" {
		t.Fatalf("личность = %+v", id)
	}
}

// Telegram-ID не должен попадать в адрес ни в каком виде: адрес видят
// история браузера, журналы прокси и Referer.
func TestStartDoesNotLeakTelegramIDInURL(t *testing.T) {
	h := newStart(t, nextcloud.NewCodes(), false)

	r := authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	loc := w.Header().Get("Location")
	for _, secret := range []string{"270369579", "ilvesbogdan", "Bogdan"} {
		if strings.Contains(loc, secret) {
			t.Fatalf("в адресе видно %q: %s", secret, loc)
		}
	}
}

// Адрес с кодом не должен оседать в кэше и не должен утекать в Referer.
func TestStartForbidsCachingAndReferrer(t *testing.T) {
	h := newStart(t, nextcloud.NewCodes(), false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil)))

	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
	if rp := w.Header().Get("Referrer-Policy"); rp != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", rp)
	}
}

// Обработчик стоит за Guard, и попасть сюда без личности можно только по
// ошибке сборки роутера. Молча пускать такой запрос нельзя.
func TestStartRefusesWithoutClaims(t *testing.T) {
	h := newStart(t, nextcloud.NewCodes(), false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nextcloud", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("код ответа %d, ожидался 500", w.Code)
	}
}

// При включённой привязке код обязан запоминать адрес браузера.
func TestStartBindsCodeToClientIP(t *testing.T) {
	codes := nextcloud.NewCodes()
	h := newStart(t, codes, true)

	r := authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil))
	r.Header.Set("X-Forwarded-For", "192.168.8.5")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")

	if _, err := codes.Redeem(code, "", "10.0.0.1"); err == nil {
		t.Fatal("код обменян с чужого адреса")
	}
}

func newRedeem(codes *nextcloud.Codes) *nextcloud.RedeemHandler {
	return &nextcloud.RedeemHandler{Codes: codes, Secret: testSecret, Log: quiet()}
}

func redeemRequest(t *testing.T, code, clientIP, secret string) *http.Request {
	t.Helper()
	return redeemRequestWithNonce(t, code, "", clientIP, secret)
}

func redeemRequestWithNonce(t *testing.T, code, nonce, clientIP, secret string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"code": code, "nonce": nonce, "client_ip": clientIP,
	})
	r := httptest.NewRequest(http.MethodPost, nextcloud.RedeemPath, strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		r.Header.Set(nextcloud.SecretHeader, secret)
	}
	return r
}

func TestRedeemReturnsIdentity(t *testing.T) {
	codes := nextcloud.NewCodes()
	code, _, _ := codes.Issue(ident(), "", false)
	h := newRedeem(codes)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, redeemRequest(t, code, "", testSecret))

	if w.Code != http.StatusOK {
		t.Fatalf("код ответа %d: %s", w.Code, w.Body.String())
	}
	var got struct {
		UID         string `json:"uid"`
		DisplayName string `json:"display_name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("ответ не разбирается: %v", err)
	}
	if got.UID != "tg42" || got.DisplayName != "Алиса Иванова" {
		t.Fatalf("получено %+v", got)
	}
}

// Без секрета обмен невозможен: именно это делает украденный код бесполезным.
func TestRedeemRequiresSecret(t *testing.T) {
	cases := map[string]string{
		"без заголовка": "",
		"чужой секрет":  "секрет-длиной-больше-тридцати-двух-символов-но-другой",
		"почти верный":  testSecret + "x",
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			codes := nextcloud.NewCodes()
			code, _, _ := codes.Issue(ident(), "", false)
			h := newRedeem(codes)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, redeemRequest(t, code, "", secret))

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("код ответа %d, ожидался 401", w.Code)
			}
			// Код обязан уцелеть: неудачная попытка чужого не должна лишать
			// резидента возможности войти.
			if _, err := codes.Redeem(code, "", ""); err != nil {
				t.Fatalf("код сожжён неавторизованной попыткой: %v", err)
			}
		})
	}
}

// Пустой секрет в конфигурации не должен открывать обмен всем подряд.
func TestRedeemRefusesWithEmptyConfiguredSecret(t *testing.T) {
	codes := nextcloud.NewCodes()
	code, _, _ := codes.Issue(ident(), "", false)
	h := &nextcloud.RedeemHandler{Codes: codes, Secret: "", Log: quiet()}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, redeemRequest(t, code, "", ""))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("код ответа %d, ожидался 401", w.Code)
	}
}

// Повтор обмена — основная защита от replay — обязан отказывать.
func TestRedeemRejectsReplay(t *testing.T) {
	codes := nextcloud.NewCodes()
	code, _, _ := codes.Issue(ident(), "", false)
	h := newRedeem(codes)

	first := httptest.NewRecorder()
	h.ServeHTTP(first, redeemRequest(t, code, "", testSecret))
	if first.Code != http.StatusOK {
		t.Fatalf("первый обмен: %d", first.Code)
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, redeemRequest(t, code, "", testSecret))
	if second.Code == http.StatusOK {
		t.Fatal("повторный обмен прошёл успешно")
	}
}

// Причина отказа наружу не уходит: различать «код не тот» и «код с чужого
// адреса» значило бы подсказывать, что именно подбирать.
func TestRedeemHidesFailureReason(t *testing.T) {
	codes := nextcloud.NewCodes()
	bound, _, _ := codes.Issue(ident(), "192.168.8.5", false)
	h := newRedeem(codes)

	wrongIP := httptest.NewRecorder()
	h.ServeHTTP(wrongIP, redeemRequest(t, bound, "10.0.0.1", testSecret))
	unknown := httptest.NewRecorder()
	h.ServeHTTP(unknown, redeemRequest(t, "выдуманный", "10.0.0.1", testSecret))

	// Статус — такой же оракул, как и тело: по нему подбирают, даже не читая
	// ответ. Прошлая версия теста смотрела только на тело и пропускала это.
	if wrongIP.Code != unknown.Code {
		t.Fatalf("статусы различаются (%d и %d) и выдают причину отказа",
			wrongIP.Code, unknown.Code)
	}
	if wrongIP.Code != http.StatusForbidden {
		t.Fatalf("код ответа %d, ожидался 403", wrongIP.Code)
	}
	for _, w := range []*httptest.ResponseRecorder{wrongIP, unknown} {
		body := w.Body.String()
		if strings.Contains(body, "адрес") || strings.Contains(body, "tg42") {
			t.Fatalf("в ответе есть подробности: %q", body)
		}
	}
}

func TestRedeemRejectsGet(t *testing.T) {
	h := newRedeem(nextcloud.NewCodes())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, nextcloud.RedeemPath, nil))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("код ответа %d, ожидался 405", w.Code)
	}
}

func TestRedeemRejectsBrokenBody(t *testing.T) {
	h := newRedeem(nextcloud.NewCodes())
	r := httptest.NewRequest(http.MethodPost, nextcloud.RedeemPath, strings.NewReader("не json"))
	r.Header.Set(nextcloud.SecretHeader, testSecret)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("код ответа %d, ожидался 400", w.Code)
	}
}

func TestClientIPPrefersForwardedFor(t *testing.T) {
	cases := []struct {
		name string
		xff  string
		addr string
		want string
	}{
		{"без заголовка", "", "192.168.8.5:54321", "192.168.8.5"},
		{"один адрес", "203.0.113.7", "10.0.0.1:1", "203.0.113.7"},
		{"цепочка", "203.0.113.7, 10.0.0.1", "10.0.0.1:1", "203.0.113.7"},
		{"с пробелами", "  203.0.113.7 ,10.0.0.1", "10.0.0.1:1", "203.0.113.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.addr
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := nextcloud.ClientIP(r); got != c.want {
				t.Fatalf("получено %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// Кука с nonce — та часть привязки, которой у постороннего нет. Без неё
// резидент мог бы получить код на свой аккаунт и заставить чужой браузер
// открыть ссылку с ним: жертва оказалась бы в чужом Nextcloud.
func TestStartSetsNonceCookie(t *testing.T) {
	codes := nextcloud.NewCodes()
	h := newStart(t, codes, false)
	h.CookieDomain = "akiba.space"

	w := httptest.NewRecorder()
	r := authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil))
	r.Header.Set("X-Forwarded-Proto", "https")
	h.ServeHTTP(w, r)

	var nonce *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == nextcloud.NonceCookie {
			nonce = c
		}
	}
	if nonce == nil {
		t.Fatal("кука с nonce не выдана")
	}
	if nonce.Domain != "akiba.space" {
		t.Errorf("Domain = %q: до Nextcloud такая кука не доедет", nonce.Domain)
	}
	if !nonce.HttpOnly {
		t.Error("кука доступна скриптам страницы")
	}
	if !nonce.Secure {
		t.Error("кука без Secure на https-портале")
	}
	// Lax обязателен: Strict не пришлют при переходе на соседнее имя, и вход
	// перестал бы работать вовсе.
	if nonce.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, ожидался Lax", nonce.SameSite)
	}
	if nonce.MaxAge <= 0 || nonce.MaxAge > 120 {
		t.Errorf("MaxAge = %d: кука должна жить не дольше самого кода", nonce.MaxAge)
	}

	// И код без этой куки не обменивается.
	loc, _ := url.Parse(w.Header().Get("Location"))
	if _, err := codes.Redeem(loc.Query().Get("code"), "", ""); err == nil {
		t.Fatal("код обменян без nonce из куки")
	}
}

// Обмен с правильным nonce проходит целиком, через HTTP-обработчик.
func TestRedeemAcceptsNonceFromCookie(t *testing.T) {
	codes := nextcloud.NewCodes()
	start := newStart(t, codes, false)
	start.CookieDomain = "akiba.space"

	issued := httptest.NewRecorder()
	start.ServeHTTP(issued, authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil)))
	loc, _ := url.Parse(issued.Header().Get("Location"))
	code := loc.Query().Get("code")

	var nonce string
	for _, c := range issued.Result().Cookies() {
		if c.Name == nextcloud.NonceCookie {
			nonce = c.Value
		}
	}

	w := httptest.NewRecorder()
	newRedeem(codes).ServeHTTP(w, redeemRequestWithNonce(t, code, nonce, "", testSecret))

	if w.Code != http.StatusOK {
		t.Fatalf("код ответа %d: %s", w.Code, w.Body.String())
	}
}

// Без общего домена кука до Nextcloud не доедет, и привязки по nonce не будет.
// Притворяться, что она работает, нельзя — иначе вход просто не заработает.
func TestStartSkipsNonceWithoutCommonDomain(t *testing.T) {
	codes := nextcloud.NewCodes()
	h := newStart(t, codes, false) // CookieDomain пуст

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil)))

	for _, c := range w.Result().Cookies() {
		if c.Name == nextcloud.NonceCookie {
			t.Fatal("выдана кука, которая до Nextcloud не доедет")
		}
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if _, err := codes.Redeem(loc.Query().Get("code"), "", ""); err != nil {
		t.Fatalf("код не обменивается при выключенной привязке: %v", err)
	}
}

func TestNonceDomain(t *testing.T) {
	cases := []struct {
		name          string
		portal, cloud string
		want          string
	}{
		{"общий домен", "inside.akiba.space", "nextcloud.akiba.space", "akiba.space"},
		{"с портами", "inside.akiba.space:8080", "nextcloud.akiba.space:443", "akiba.space"},
		{"Nextcloud по IP", "inside.akiba.space", "192.168.8.43:9090", ""},
		{"портал по IP", "192.168.8.82", "nextcloud.akiba.space", ""},
		{"разные домены", "inside.akiba.space", "cloud.example.com", ""},
		{"односегментные", "localhost", "localhost", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextcloud.NonceDomain(c.portal, c.cloud); got != c.want {
				t.Fatalf("получено %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// Домен у куки общий — иначе она не доедет до Nextcloud, — поэтому путь
// обязан быть узким: иначе её получал бы каждый запрос к каждому поддомену.
func TestNonceCookieIsScopedToSSOPath(t *testing.T) {
	h := newStart(t, nextcloud.NewCodes(), false)
	h.CookieDomain = "akiba.space"

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil)))

	var nonce *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == nextcloud.NonceCookie {
			nonce = c
		}
	}
	if nonce == nil {
		t.Fatal("кука с nonce не выдана")
	}
	if nonce.Path != h.SSOPath {
		t.Fatalf("Path = %q, ожидался %q", nonce.Path, h.SSOPath)
	}
	// Путь обязан совпадать с тем, куда уходит браузер: иначе браузер куку
	// просто не пришлёт, и вход перестанет работать.
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location не разбирается: %v", err)
	}
	if !strings.HasPrefix(loc.Path, nonce.Path) {
		t.Fatalf("кука на %q не дойдёт до %q", nonce.Path, loc.Path)
	}
}

// Портал в локальной сети открывают и по http. Кука с Secure на такой
// странице браузером не сохраняется вовсе, а значит nonce не доедет до
// Nextcloud и вход будет отказывать всегда — молча, без следов в журнале
// шлюза, кроме отказа в обмене.
func TestNonceCookieIsNotSecureOverPlainHTTP(t *testing.T) {
	h := newStart(t, nextcloud.NewCodes(), false)
	h.CookieDomain = "akiba.space"

	w := httptest.NewRecorder()
	// Ни TLS, ни X-Forwarded-Proto — так выглядит запрос из локальной сети.
	h.ServeHTTP(w, authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil)))

	for _, c := range w.Result().Cookies() {
		if c.Name == nextcloud.NonceCookie && c.Secure {
			t.Fatal("кука с Secure выдана по http — браузер её не сохранит")
		}
	}
}

// А по https флаг обязан стоять: иначе куку можно подсунуть с http-страницы
// соседнего поддомена.
func TestNonceCookieIsSecureOverHTTPS(t *testing.T) {
	h := newStart(t, nextcloud.NewCodes(), false)
	h.CookieDomain = "akiba.space"

	w := httptest.NewRecorder()
	r := authorized(httptest.NewRequest(http.MethodGet, "/nextcloud", nil))
	r.Header.Set("X-Forwarded-Proto", "https")
	h.ServeHTTP(w, r)

	var found bool
	for _, c := range w.Result().Cookies() {
		if c.Name == nextcloud.NonceCookie {
			found = true
			if !c.Secure {
				t.Fatal("кука без Secure на https-портале")
			}
		}
	}
	if !found {
		t.Fatal("кука с nonce не выдана")
	}
}
