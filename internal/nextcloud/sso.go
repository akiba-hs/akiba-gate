package nextcloud

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/akiba-hs/akiba-gate/internal/auth"
)

// StartPath — адрес, с которого начинается вход: здесь выдаётся одноразовый
// код и браузер уходит в Nextcloud.
const StartPath = "/nextcloud"

// RedeemPath — служебный адрес, по которому приложение-адаптер обменивает код.
//
// Он открыт без куки авторизации намеренно: обращается к нему не браузер, а
// сам Nextcloud, у которого никакой куки резидента нет и быть не должно.
// Право на обмен доказывается общим секретом в заголовке.
const RedeemPath = "/nextcloud/redeem"

// SecretHeader — заголовок с общим секретом.
const SecretHeader = "X-Akiba-SSO-Secret"

// maxRedeemBody ограничивает тело запроса на обмен: там три коротких поля.
const maxRedeemBody = 4 << 10

// NonceCookie — имя куки с nonce, привязывающим код к браузеру.
//
// Кука ставится на общий родительский домен портала и Nextcloud, чтобы её
// увидело приложение-адаптер: оно живёт на соседнем имени и читает её из
// запроса браузера, а затем пересылает шлюзу при обмене.
const NonceCookie = "akiba_nc_sso"

// StartHandler выдаёт одноразовый код и отправляет браузер в Nextcloud.
//
// Стоит за Guard и за проверкой права на сервис, поэтому здесь личность уже
// известна и проверена. Код кладётся в адрес, Telegram-ID в него не попадает
// ни в каком виде.
type StartHandler struct {
	Codes *Codes
	// PublicURL — адрес Nextcloud, каким его видит браузер.
	PublicURL *url.URL
	// SSOPath — путь приложения-адаптера внутри Nextcloud.
	SSOPath string
	// BindIP включает дополнительную привязку кода к адресу браузера.
	BindIP bool
	// CookieDomain — домен для куки с nonce. Пустой означает, что общего
	// родительского домена у портала и Nextcloud нет (например, Nextcloud
	// адресуется по IP): тогда кука ставится host-only и до адаптера не
	// доедет, а привязка по nonce отключается. См. NonceDomain.
	CookieDomain string
	Log          *slog.Logger
}

func (h *StartHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		// Сюда можно попасть только через Guard — значит, ошибка сборки роутера.
		h.Log.Error("вход в Nextcloud вызван без проверки авторизации")
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}

	var clientIP string
	if h.BindIP {
		clientIP = ClientIP(r)
	}
	code, nonce, err := h.Codes.Issue(Identity{
		UID:         claims.UID(),
		DisplayName: claims.DisplayName(),
		Username:    claims.Username,
	}, clientIP, h.CookieDomain != "")
	if err != nil {
		h.Log.Error("не удалось выдать код входа в Nextcloud",
			"error", err, "user", claims.UID())
		http.Error(w, "Nextcloud недоступен, попробуйте позже", http.StatusServiceUnavailable)
		return
	}

	// Кука с nonce — то, чего нет у постороннего, приславшего чужой код.
	// Живёт столько же, сколько сам код: дольше она не нужна никому.
	if nonce != "" {
		http.SetCookie(w, &http.Cookie{
			Name:  NonceCookie,
			Value: nonce,
			// Путь ровно тот, куда сейчас уйдёт браузер. Домен здесь общий —
			// иначе кука не доедет до соседнего имени, — а значит без этого
			// ограничения её получал бы каждый запрос к каждому поддомену
			// akiba.space. Сужение до одного пути оставляет получателем ровно
			// то приложение, для которого кука и выдана.
			Path:     h.SSOPath,
			Domain:   h.CookieDomain,
			MaxAge:   int(codeTTL.Seconds()),
			HttpOnly: true,
			// Флаг ставится по схеме текущего запроса, а не по настройке.
			// Портал открывают и по http — в локальной сети это разрешено,
			// — а куку с Secure браузер с такой страницы просто не сохранит,
			// и вход отказал бы, не оставив следа нигде, кроме отказа в
			// обмене. Без Secure она всё равно уйдёт на https-адрес
			// Nextcloud: флаг ограничивает отправку, а не приём.
			Secure: auth.RequestScheme(r) == "https",
			// Lax, а не Strict: браузер обязан прислать куку при переходе
			// верхнего уровня на Nextcloud, а именно так этот вход и работает.
			SameSite: http.SameSiteLaxMode,
		})
	}

	target := *h.PublicURL
	target.Path = h.SSOPath
	target.RawQuery = url.Values{"code": {code}}.Encode()

	h.Log.Info("резидент отправлен на вход в Nextcloud",
		"user", claims.UID(), "username", claims.Username)
	// no-store обязателен: иначе адрес с кодом осядет в истории и в кэше.
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}

// RedeemHandler обменивает код на личность по запросу приложения-адаптера.
type RedeemHandler struct {
	Codes *Codes
	// Secret — общий секрет с приложением. Без него украденный код
	// бесполезен: обменять его может только тот, кто знает секрет.
	Secret string
	Log    *slog.Logger
}

// redeemRequest — то, что присылает приложение-адаптер.
type redeemRequest struct {
	Code string `json:"code"`
	// Nonce — значение куки, которую браузер принёс в Nextcloud вместе с
	// переходом. Доказывает, что код предъявляет тот же браузер, который его
	// получал.
	Nonce string `json:"nonce"`
	// ClientIP — адрес браузера, каким его видит Nextcloud. Сверяется с тем,
	// с которого код запрашивали.
	ClientIP string `json:"client_ip"`
}

// redeemResponse — то, что нужно приложению, чтобы завести и залогинить
// человека. Ничего лишнего: Telegram-ID наружу не уходит.
type redeemResponse struct {
	UID         string `json:"uid"`
	DisplayName string `json:"display_name"`
}

func (h *RedeemHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}
	// Сравнение постоянного времени: обычное == позволяет подобрать секрет
	// по времени ответа, байт за байтом.
	got := r.Header.Get(SecretHeader)
	if h.Secret == "" || subtle.ConstantTimeCompare([]byte(got), []byte(h.Secret)) != 1 {
		// В журнал идёт RemoteAddr, а не ClientIP: X-Forwarded-For пишет
		// клиент, и подбирающий секрет мог бы вписать туда что угодно —
		// единственная строка, по которой атаку видно, оказалась бы
		// полностью в его власти.
		h.Log.Warn("обмен кода Nextcloud отклонён: неверный секрет",
			"remote_addr", remoteAddr(r))
		http.Error(w, "не авторизовано", http.StatusUnauthorized)
		return
	}

	var req redeemRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRedeemBody)).Decode(&req); err != nil {
		h.Log.Warn("не удалось разобрать запрос обмена кода", "error", err)
		http.Error(w, "некорректный запрос", http.StatusBadRequest)
		return
	}

	identity, err := h.Codes.Redeem(req.Code, req.Nonce, req.ClientIP)
	if err != nil {
		// Наружу и причина, и код ответа одинаковы для всех отказов.
		// Разные статусы на «кода нет» и «код не того браузера» были бы
		// оракулом: по нему подбирают, даже не читая тело ответа. В журнале
		// причина есть — там она и нужна.
		h.Log.Warn("обмен кода Nextcloud отклонён", "error", err,
			// Оба адреса рядом: расхождение между тем, что видит шлюз, и тем,
			// что прислал Nextcloud, — самая частая причина отказа, и без
			// пары значений её не диагностировать.
			"client_ip_from_nextcloud", req.ClientIP,
			"remote_addr", remoteAddr(r),
			// Не значение, а только факт: пустой nonce означает, что кука не
			// доехала до Nextcloud, а непустой — что доехала не та. Причины
			// разные, чинятся по-разному, а по одному тексту ошибки их не
			// различить.
			"nonce_present", req.Nonce != "")
		http.Error(w, "код недействителен", http.StatusForbidden)
		return
	}

	h.Log.Info("код входа в Nextcloud обменян",
		"user", identity.UID, "username", identity.Username)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(redeemResponse{
		UID:         identity.UID,
		DisplayName: identity.DisplayName,
	})
}

// NonceDomain возвращает домен для куки с nonce: общий родительский домен
// портала и Nextcloud.
//
// Кука должна доехать до соседнего имени (nextcloud.akiba.space), поэтому
// ставится на "akiba.space". Если общего домена нет — например, Nextcloud
// адресуется по IP, как при локальной отладке, — возвращается пустая строка:
// привязка по nonce в такой конфигурации невозможна, и притворяться, что она
// работает, нельзя.
func NonceDomain(portalHost, nextcloudHost string) string {
	portal := registrableSuffix(hostOnly(portalHost))
	cloud := registrableSuffix(hostOnly(nextcloudHost))
	if portal == "" || portal != cloud {
		return ""
	}
	return portal
}

// registrableSuffix возвращает два последних сегмента имени: "akiba.space" из
// "inside.akiba.space". Для адреса-IP и односегментного имени — пустая строка.
func registrableSuffix(host string) string {
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// hostOnly отрезает порт, если он есть.
func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

// remoteAddr возвращает адрес соединения — тот, что подделать нельзя.
func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ClientIP возвращает адрес того, кто обратился к шлюзу.
//
// X-Forwarded-For учитывается: шлюз стоит за Traefik, и без этого все
// резиденты выглядели бы одним адресом прокси — привязка кода к клиенту
// перестала бы что-либо значить. Берётся первый элемент цепочки: его ставит
// самый дальний доверенный прокси.
//
// Заголовок пишет клиент, и подделать его можно. Для привязки это не
// страшно: подделав адрес, атакующий добьётся лишь того, что его собственный
// код будет привязан к чужому адресу — то есть навредит себе.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
