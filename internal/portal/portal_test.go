package portal_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/portal"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

func newPortal(t *testing.T) (*portal.Handler, testsupport.KeyPair) {
	t.Helper()
	return newPortalWithServices(t, access.All())
}

// newPortalWithServices собирает портал с заданным набором доступных сервисов.
func newPortalWithServices(t *testing.T, allowed []access.ID) (*portal.Handler, testsupport.KeyPair) {
	t.Helper()
	kp := testsupport.NewKeyPair(t)
	v, err := auth.NewVerifier(kp.PublicPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	base, err := url.Parse("https://inside.akiba.space")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	authURL, err := url.Parse("https://auth.akiba.space")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return &portal.Handler{
		Verifier:   v,
		CookieName: "token",
		AuthURL:    authURL,
		Hosts:      auth.HostPolicy{Base: base},
		Policy:     access.ResidentPolicy{Services: allowed},
		Catalog: access.Catalog{
			JellyfinURL:  "/sso/jellyfin",
			QbitURL:      "/qbittorrent/",
			NextcloudURL: "/nextcloud",
		},
		Texts:    testsupport.StaticTexts{},
		Audience: auth.NewSeen(),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, kp
}

// get выполняет запрос к порталу от имени владельца токена (пустой — аноним).
func get(t *testing.T, h http.Handler, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		// Иначе httptest подставит example.com, портал сочтёт хост чужим и
		// покажет предупреждение вместо обычной страницы.
		target = "https://inside.akiba.space" + target
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		r.AddCookie(&http.Cookie{Name: "token", Value: token})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPortalHidesServicesFromAnonymous(t *testing.T) {
	h, _ := newPortal(t)
	w := get(t, h, "/", "")

	if w.Code != http.StatusOK {
		t.Fatalf("код %d", w.Code)
	}
	body := w.Body.String()
	for _, forbidden := range []string{"/sso/jellyfin", "/qbittorrent/", "/nextcloud", "Jellyfin", "qBittorrent"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("в анонимной странице найдено %q", forbidden)
		}
	}
	if !strings.Contains(body, "auth.akiba.space") {
		t.Fatal("нет ссылки на вход")
	}
}

func TestPortalShowsServicesToResident(t *testing.T) {
	h, kp := newPortal(t)
	w := get(t, h, "/", kp.ResidentToken(t))

	body := w.Body.String()
	for _, want := range []string{"/sso/jellyfin", "/qbittorrent/", "/nextcloud", "Alice Example", "@alice"} {
		if !strings.Contains(body, want) {
			t.Fatalf("на странице нет %q", want)
		}
	}
	if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("Cache-Control = %q, персональная страница не должна кэшироваться", got)
	}
}

func TestPortalHidesServicesFromNonResident(t *testing.T) {
	h, kp := newPortal(t)
	token := kp.Token(t, testsupport.TokenOptions{Username: "bob", FirstName: "Bob", IsResident: false})

	body := get(t, h, "/", token).Body.String()

	if strings.Contains(body, "/sso/jellyfin") {
		t.Fatal("не-резиденту показаны ссылки на сервисы")
	}
	if !strings.Contains(body, "не резидент") {
		t.Fatalf("нет объяснения, почему сервисы недоступны:\n%s", body)
	}
}

func TestPortalTreatsBadTokenAsAnonymous(t *testing.T) {
	h, _ := newPortal(t)
	body := get(t, h, "/", "ne.nastoyaschiy.token").Body.String()

	if strings.Contains(body, "/sso/jellyfin") {
		t.Fatal("битый токен открыл доступ к ссылкам")
	}
	if !strings.Contains(body, "Войти через Telegram") {
		t.Fatal("не предложен вход")
	}
}

func TestPortalShowsNotResidentError(t *testing.T) {
	h, _ := newPortal(t)
	body := get(t, h, "/?error=not_resident", "").Body.String()

	if !strings.Contains(body, "не состоите в чате резидентов") {
		t.Fatalf("сообщение об ошибке не показано:\n%s", body)
	}
}

func TestPortalReturns404ForUnknownPath(t *testing.T) {
	h, _ := newPortal(t)
	if w := get(t, h, "/unknown", ""); w.Code != http.StatusNotFound {
		t.Fatalf("код %d, ожидался 404", w.Code)
	}
}

func TestPortalLoginLinkReturnsToPortal(t *testing.T) {
	h, _ := newPortal(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Host", "inside.akiba.space")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	// Локальный доступ идёт по http — ссылка возврата обязана это учитывать.
	if !strings.Contains(w.Body.String(), "redirect_uri=http%3A%2F%2Finside.akiba.space%2F") {
		t.Fatalf("неверная ссылка возврата:\n%s", w.Body.String())
	}
}

// Фотография приходит из данных Telegram; в src не должно попадать ничего,
// кроме http(s).
func TestPortalRejectsNonHTTPPhotoURL(t *testing.T) {
	h, kp := newPortal(t)
	token := kp.Token(t, testsupport.TokenOptions{
		FirstName: "Eve", IsResident: true, PhotoURL: "javascript:alert(1)",
	})

	body := get(t, h, "/", token).Body.String()

	if strings.Contains(body, "javascript:") {
		t.Fatalf("в страницу попала опасная схема:\n%s", body)
	}
}

func TestPortalRendersHTTPSPhotoURL(t *testing.T) {
	h, kp := newPortal(t)
	token := kp.Token(t, testsupport.TokenOptions{
		FirstName: "Eve", IsResident: true, PhotoURL: "https://t.me/photo.jpg",
	})

	if !strings.Contains(get(t, h, "/", token).Body.String(), "https://t.me/photo.jpg") {
		t.Fatal("нормальная фотография не отрисована")
	}
}

// ForwardAuth уводит не-резидента на портал с ?error=not_resident, и человек
// приходит туда уже авторизованным. Объяснение обязано показываться именно
// в этой ветке, а не только анонимной.
func TestPortalShowsErrorToAuthenticatedNonResident(t *testing.T) {
	h, kp := newPortal(t)
	token := kp.Token(t, testsupport.TokenOptions{Username: "bob", FirstName: "Bob", IsResident: false})

	body := get(t, h, "/?error=not_resident", token).Body.String()

	if !strings.Contains(body, "не состоите в чате резидентов") {
		t.Fatalf("объяснение не показано авторизованному не-резиденту:\n%s", body)
	}
}

// Проверка хоста была только в ForwardAuth, а портал строил ссылку возврата
// из заголовка без неё — и подставленный Host давал ссылку на настоящий
// auth.akiba.space с чужим адресом возврата.
func TestPortalRejectsForeignHostInLoginLink(t *testing.T) {
	h, _ := newPortal(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "evil.example"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	body := w.Body.String()
	if strings.Contains(body, "evil.example") {
		t.Fatalf("посторонний хост попал в ссылку возврата:\n%s", body)
	}
	if !strings.Contains(body, "inside.akiba.space") {
		t.Fatal("не выполнен откат на канонический адрес портала")
	}
}

// Портал, открытый по чужому имени (например, по голому IP), не должен
// показывать кнопку входа: кука выдаётся на домен akiba.space, на IP браузер
// её не отправит, и человек попадёт в круг «войти → снова кнопка войти».
// Именно так это и выглядело на живом запуске.
func TestPortalWarnsWhenOpenedByWrongHost(t *testing.T) {
	h, _ := newPortal(t)

	r := httptest.NewRequest(http.MethodGet, "http://192.168.8.82/", nil)
	r.Host = "192.168.8.82"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("код %d", w.Code)
	}
	if strings.Contains(body, "Войти через Telegram") {
		t.Error("на постороннем имени показана кнопка входа, ведущая в никуда")
	}
	if !strings.Contains(body, "https://inside.akiba.space/") {
		t.Errorf("не предложен канонический адрес; тело: %q", body)
	}
}

// На своём имени всё как было: кнопка входа на месте, предупреждения нет.
func TestPortalKeepsLoginButtonOnCanonicalHost(t *testing.T) {
	h, _ := newPortal(t)

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !strings.Contains(w.Body.String(), "Войти через Telegram") {
		t.Error("на каноническом имени пропала кнопка входа")
	}
}

// Предупреждение о чужом адресе обязано показываться и вошедшему тоже.
// Раньше оно жило только в анонимной ветке, и это стоило дорого: портал,
// открытый по адресу с другим портом, выглядел полностью рабочим, а
// автовход в Jellyfin и добавление торрентов молча отказывали.
func TestPortalWarnsAuthenticatedUserOnWrongHost(t *testing.T) {
	h, kp := newPortal(t)

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space:8080/", nil)
	r.Host = "inside.akiba.space:8080"
	r.AddCookie(&http.Cookie{Name: "token", Value: kp.ResidentToken(t)})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "чужому адресу") {
		t.Errorf("вошедшему не показано предупреждение о чужом адресе; тело: %q", body)
	}
	if !strings.Contains(body, "https://inside.akiba.space/") {
		t.Error("не предложен канонический адрес")
	}
}

// На своём адресе предупреждения быть не должно ни у кого.
func TestPortalStaysQuietOnCanonicalHost(t *testing.T) {
	h, kp := newPortal(t)

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: kp.ResidentToken(t)})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if strings.Contains(w.Body.String(), "чужому адресу") {
		t.Error("предупреждение показано на каноническом адресе")
	}
}

// ReturnBase существует ради ограничения auth-service: он проверяет
// redirect_uri как netloc.endswith(".akiba.space"), а netloc включает порт,
// поэтому с портала на нестандартном порту вход падал с 400. Настройка
// позволяет вернуть человека по адресу, который auth-service принимает.
func TestPortalLoginLinkUsesReturnBase(t *testing.T) {
	h, _ := newPortal(t)
	h.ReturnBase = &url.URL{Scheme: "http", Host: "inside.akiba.space"}
	h.Hosts = auth.HostPolicy{
		Base:    &url.URL{Scheme: "http", Host: "inside.akiba.space:8080"},
		Allowed: []string{"inside.akiba.space:8080"},
	}

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space:8080/", nil)
	r.Host = "inside.akiba.space:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, url.QueryEscape("http://inside.akiba.space/")) {
		t.Errorf("в ссылке входа нет настроенного адреса возврата; тело: %q", body)
	}
	if strings.Contains(body, url.QueryEscape("http://inside.akiba.space:8080/")) {
		t.Error("в ссылку входа попал адрес с портом — auth-service отвергнет его с 400")
	}
}

// Когда возврат после входа настроен на посторонний адрес, портал обязан
// предупредить: иначе человек входит, оказывается на чужой странице и
// считает, что вход не сработал. Ровно так это и выглядело на живом запуске.
func TestPortalWarnsWhenLoginReturnsElsewhere(t *testing.T) {
	h, _ := newPortal(t)
	h.ReturnBase = &url.URL{Scheme: "https", Host: "auth.akiba.space"}

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "эта страница дождётся") {
		t.Errorf("нет предупреждения о возврате на чужую страницу; тело: %q", body)
	}
	if !strings.Contains(body, "/whoami") {
		t.Error("страница не опрашивает /whoami и не обновится сама после входа")
	}
	if !strings.Contains(body, `target="_blank"`) {
		t.Error("вход не открывается в новой вкладке, портал потеряется")
	}
}

// Возврат на другое НАШЕ имя (без порта, который принимает auth-service) —
// это возврат на портал, а не на чужую страницу: auth-service отдаёт 303
// прямо сюда. Значит ни новой вкладки, ни опроса /whoami не нужно.
func TestPortalKeepsPlainLoginWhenReturnBaseIsOurs(t *testing.T) {
	h, _ := newPortal(t)
	h.ReturnBase = &url.URL{Scheme: "http", Host: "inside.akiba.space"}
	h.Hosts = auth.HostPolicy{
		Base:    &url.URL{Scheme: "http", Host: "inside.akiba.space:8080"},
		Allowed: []string{"inside.akiba.space:8080", "inside.akiba.space"},
	}

	r := httptest.NewRequest(http.MethodGet, "http://inside.akiba.space:8080/", nil)
	r.Host = "inside.akiba.space:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if strings.Contains(body, `target="_blank"`) {
		t.Error("вход открывается в новой вкладке, хотя возврат ведёт на портал")
	}
	if strings.Contains(body, "/whoami") {
		t.Error("страница опрашивает /whoami, хотя auth-service вернёт человека сюда сам")
	}
	// Адрес возврата при этом всё равно без порта — иначе auth-service
	// ответит 400 и вход не состоится вовсе.
	if !strings.Contains(body, url.QueryEscape("http://inside.akiba.space/")) {
		t.Errorf("в ссылке входа нет настроенного адреса возврата; тело: %q", body)
	}
}

// Без такой настройки поведение прежнее: обычная кнопка в той же вкладке.
func TestPortalKeepsPlainLoginButtonByDefault(t *testing.T) {
	h, _ := newPortal(t)

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if strings.Contains(body, `target="_blank"`) {
		t.Error("вход открывается в новой вкладке без надобности")
	}
	if !strings.Contains(body, "Войти через Telegram") {
		t.Error("пропала кнопка входа")
	}
}

// /whoami отвечает про самого спрашивающего и ни про кого больше: портал
// опрашивает его, пока человек входит в соседней вкладке.
func TestWhoAmIReportsAnonymous(t *testing.T) {
	h, _ := newPortal(t)

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/whoami", nil)
	w := httptest.NewRecorder()
	h.WhoAmI(w, r)

	if got := w.Body.String(); !strings.Contains(got, `"authenticated":false`) {
		t.Fatalf("тело = %q", got)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, ответ персональный и кэшироваться не должен", cc)
	}
}

func TestWhoAmIReportsResident(t *testing.T) {
	h, kp := newPortal(t)

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/whoami", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: kp.ResidentToken(t)})
	w := httptest.NewRecorder()
	h.WhoAmI(w, r)

	got := w.Body.String()
	if !strings.Contains(got, `"authenticated":true`) || !strings.Contains(got, `"resident":true`) {
		t.Fatalf("тело = %q", got)
	}
}

// Чужой или протухший токен — это аноним, а не ошибка: иначе вкладка портала
// крутилась бы в ожидании входа, который уже не состоится.
func TestWhoAmITreatsBadTokenAsAnonymous(t *testing.T) {
	h, _ := newPortal(t)

	r := httptest.NewRequest(http.MethodGet, "https://inside.akiba.space/whoami", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: "не.настоящий.токен"})
	w := httptest.NewRecorder()
	h.WhoAmI(w, r)

	if got := w.Body.String(); !strings.Contains(got, `"authenticated":false`) {
		t.Fatalf("тело = %q", got)
	}
}

// Резидент без единого доступного сервиса должен видеть поздравление, а не
// пустое место, из которого непонятно, сломалось что-то или нет.
func TestPortalCheersResidentWithoutServices(t *testing.T) {
	h, kp := newPortalWithServices(t, nil)
	body := get(t, h, "/", kp.ResidentToken(t)).Body.String()

	if !strings.Contains(body, testsupport.Messages().NoServices) {
		t.Fatalf("нет поздравления для резидента без сервисов; тело: %q", body)
	}
}

// Как только доступен хоть один сервис, поздравления быть не должно.
func TestPortalHidesCheerWhenServiceAvailable(t *testing.T) {
	h, kp := newPortalWithServices(t, []access.ID{access.Jellyfin})
	body := get(t, h, "/", kp.ResidentToken(t)).Body.String()

	if strings.Contains(body, testsupport.Messages().NoServices) {
		t.Fatal("поздравление показано при доступном сервисе")
	}
	if !strings.Contains(body, "/sso/jellyfin") {
		t.Fatal("нет карточки доступного сервиса")
	}
}

// Портал показывает ровно те карточки, что разрешила политика.
func TestPortalShowsOnlyAllowedServices(t *testing.T) {
	h, kp := newPortalWithServices(t, []access.ID{access.QBittorrent})
	body := get(t, h, "/", kp.ResidentToken(t)).Body.String()

	if !strings.Contains(body, "/qbittorrent/") {
		t.Error("нет карточки разрешённого сервиса")
	}
	if strings.Contains(body, "/sso/jellyfin") || strings.Contains(body, "/nextcloud") {
		t.Errorf("показаны закрытые сервисы; тело: %q", body)
	}
}

// Тексты берутся из файла переводов, а не зашиты в шаблон.
func TestPortalRendersTextsFromMessages(t *testing.T) {
	h, _ := newPortal(t)
	custom := testsupport.Messages()
	custom.PortalTitle = "Совершенно другой заголовок"
	custom.LoginButton = "Совершенно другая кнопка"
	h.Texts = testsupport.StaticTexts{M: custom}

	body := get(t, h, "/", "").Body.String()

	for _, want := range []string{custom.PortalTitle, custom.LoginButton} {
		if !strings.Contains(body, want) {
			t.Errorf("в странице нет текста %q", want)
		}
	}
}

// avatarURL — типовой адрес аватарки Telegram.
const avatarURL = "https://t.me/i/userpic/320/U1U6xmdeEGqQkK-v9p-6-8-_pTsk7oM_N2-DuNPgPKA.jpg"

// avatarToken выпускает токен резидента с аватаркой.
func avatarToken(t *testing.T, kp testsupport.KeyPair) string {
	t.Helper()
	return kp.Token(t, testsupport.TokenOptions{
		TelegramID: "42424242", Username: "alice", IsResident: true,
		PhotoURL: avatarURL,
	})
}

// С заданным SOCKS5 аватарка должна идти через шлюз: прямой адрес t.me
// сообщает Telegram, кто и когда открыл портал, и у части резидентов попросту
// не открывается.
func TestPortalRoutesAvatarThroughGate(t *testing.T) {
	h, kp := newPortal(t)
	h.ProxyUserPics = true
	body := get(t, h, "/", avatarToken(t, kp)).Body.String()

	if strings.Contains(body, "t.me") {
		t.Fatalf("прямой адрес Telegram остался в странице: %q", body)
	}
	if !strings.Contains(body, "/userpic/320/") {
		t.Fatalf("аватарка не переведена на шлюз; тело: %q", body)
	}
}

// Без прокси прослойка не нужна: она только добавляет звено к запросу,
// который браузер сделает сам.
func TestPortalLinksAvatarDirectlyWithoutProxy(t *testing.T) {
	h, kp := newPortal(t)
	body := get(t, h, "/", avatarToken(t, kp)).Body.String()

	if !strings.Contains(body, avatarURL) {
		t.Fatalf("прямой адрес аватарки не подставлен; тело: %q", body)
	}
	// Именно относительный адрес шлюза: подстрока "/userpic/" встречается и
	// в самом адресе t.me ("/i/userpic/320/...").
	if strings.Contains(body, `src="/userpic/`) {
		t.Fatalf("аватарка ушла через шлюз без прокси; тело: %q", body)
	}
	// Прямая ссылка обязана уходить без Referer, иначе Telegram узнаёт
	// адрес портала у каждого, кто его открыл.
	if !strings.Contains(body, `referrerpolicy="no-referrer"`) {
		t.Errorf("у прямой ссылки нет referrerpolicy; тело: %q", body)
	}
}

// Rewrite пропускает чужие адреса как есть, поэтому даже с включённым
// прокси в src может оказаться посторонний хост — и такой ссылке нужен
// referrerpolicy, иначе адрес портала уедет наружу.
func TestPortalMarksForeignAvatarAsDirect(t *testing.T) {
	h, kp := newPortal(t)
	h.ProxyUserPics = true
	token := kp.Token(t, testsupport.TokenOptions{
		TelegramID: "42424242", Username: "alice", IsResident: true,
		PhotoURL: "https://cdn.example.org/avatar.jpg",
	})
	body := get(t, h, "/", token).Body.String()

	if !strings.Contains(body, `referrerpolicy="no-referrer"`) {
		t.Errorf("у чужой ссылки нет referrerpolicy; тело: %q", body)
	}
}

// Пока картинка едет, на её месте должен стоять скелетон: иначе имя рядом
// прыгает вбок в момент загрузки.
func TestPortalShowsAvatarSkeleton(t *testing.T) {
	h, kp := newPortal(t)
	body := get(t, h, "/", avatarToken(t, kp)).Body.String()

	if !strings.Contains(body, `class="avatar"`) {
		t.Fatalf("нет места под скелетон аватарки; тело: %q", body)
	}
	if !strings.Contains(body, "classList.add('pending')") {
		t.Fatalf("скелетон не включается скриптом; тело: %q", body)
	}
	if !strings.Contains(body, "classList.remove('pending')") {
		t.Fatalf("скелетон некому снять; тело: %q", body)
	}
}

// Без аватарки ни скелетона, ни скрипта на странице быть не должно.
func TestPortalOmitsAvatarSkeletonWithoutPhoto(t *testing.T) {
	h, kp := newPortal(t)
	body := get(t, h, "/", kp.ResidentToken(t)).Body.String()

	if strings.Contains(body, `class="avatar"`) {
		t.Errorf("скелетон показан без аватарки; тело: %q", body)
	}
}

// Кнопка выхода переехала в меню аккаунта: снизу её быть не должно, как и
// строки про срок действия входа.
func TestPortalPutsLogoutIntoAccountMenu(t *testing.T) {
	h, kp := newPortal(t)
	body := get(t, h, "/", kp.ResidentToken(t)).Body.String()

	if strings.Contains(body, "<footer") {
		t.Error("подвал остался на странице")
	}
	if strings.Contains(body, "Вход действует") {
		t.Error("строка про срок действия входа не убрана")
	}
	if !strings.Contains(body, `class="account"`) {
		t.Fatal("нет области аккаунта")
	}
	if !strings.Contains(body, `class="menu"`) {
		t.Fatal("нет выпадающего меню")
	}
	// Меню обязано открываться и с клавиатуры, иначе до выхода не добраться
	// иначе как мышью.
	if !strings.Contains(body, `tabindex="0"`) {
		t.Error("область аккаунта недоступна с клавиатуры")
	}
	if !strings.Contains(body, ":focus-within") {
		t.Error("меню не раскрывается по фокусу")
	}
	if !strings.Contains(body, testsupport.Messages().LogoutButton) {
		t.Error("в меню нет кнопки выхода")
	}
}
