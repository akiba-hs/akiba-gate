package qbit

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
	"github.com/akiba-hs/akiba-gate/internal/torrent"
)

// addPath — единственный эндпоинт qBittorrent, который нас интересует
// содержательно: именно здесь резидент добавляет торрент.
const addPath = "/api/v2/torrents/add"

// Tracker берёт добавленный торрент под наблюдение, чтобы сообщить автору,
// когда загрузка закончится. Интерфейс, а не *DownloadWatcher, чтобы прокси
// тестировался в отрыве от воркера.
type Tracker interface {
	Track(items ...Watched)
}

// Announcer сообщает в чат о добавленном торренте. Интерфейс, а не
// *tgnotify.Notifier, чтобы прокси тестировался без сети.
type Announcer interface {
	Notify(ctx context.Context, e tgnotify.Event) error
}

// Proxy проксирует qBittorrent WebUI и попутно ведёт атрибуцию добавлений.
//
// Через шлюз, а не напрямую из Traefik, — именно ради атрибуции: в самом
// qBittorrent аккаунт общий, и после прокси личность теряется навсегда.
type Proxy struct {
	basePath string
	target   *url.URL
	client   *Client
	track    Tracker
	announce Announcer
	hosts    auth.HostPolicy
	log      *slog.Logger
	rp       *httputil.ReverseProxy
	// parseSlots ограничивает число одновременных разборов тела. См. recordAdd.
	parseSlots chan struct{}
}

// maxConcurrentParses — сколько добавлений разбирается одновременно.
//
// Разбор держит в памяти до torrent.MaxAddBodySize на запрос, поэтому это
// число прямо задаёт потолок памяти под атрибуцию: четыре по 32 МиБ. Больше
// незачем — торренты добавляют штучно, а не потоком.
const maxConcurrentParses = 4

// NewProxy собирает прокси. basePath — публичный префикс ("/qbittorrent").
func NewProxy(basePath string, target *url.URL, client *Client, track Tracker,
	announce Announcer, hosts auth.HostPolicy, log *slog.Logger) *Proxy {
	p := &Proxy{
		basePath: strings.TrimSuffix(basePath, "/"),
		target:   target,
		client:   client,
		track:    track,
		announce: announce,
		hosts:    hosts,
		log:      log,

		parseSlots: make(chan struct{}, maxConcurrentParses),
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.handleError,
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// WebUI qBittorrent строит относительные пути, поэтому без завершающего
	// слэша он начнёт запрашивать ресурсы уровнем выше и получит 404 портала.
	if r.URL.Path == p.basePath {
		http.Redirect(w, r, p.basePath+"/", http.StatusMovedPermanently)
		return
	}
	// Путь с сегментами "." и ".." до бэкенда доходить не должен: бэкенд,
	// который их нормализует, увидит адрес вне префикса и, в частности,
	// разъедется с нашей проверкой на /api/v2/torrents/add.
	if hasDotSegment(r.URL.EscapedPath()) {
		http.Error(w, "некорректный путь", http.StatusBadRequest)
		return
	}
	if reason, blocked := p.apiNeedsProof(r); blocked {
		p.log.Warn("запрос к qBittorrent отклонён без подтверждения происхождения",
			"reason", reason, "method", r.Method, "path", r.URL.Path)
		http.Error(w, "межсайтовый запрос отклонён", http.StatusForbidden)
		return
	}
	if reason, blocked := p.crossSiteReason(r); blocked {
		// Собственная защита от CSRF. Ниже мы подменяем Referer и Origin на
		// адрес qBittorrent, чтобы пройти его CSRF-проверку, — и тем самым
		// снимаем её. Значит проверить происхождение запроса обязаны здесь,
		// иначе любой открытый резидентом сайт сможет управлять загрузками
		// и, через setPreferences, запускать программы на хосте.
		p.log.Warn("запрос к qBittorrent отклонён как межсайтовый",
			"reason", reason, "method", r.Method, "path", r.URL.Path)
		http.Error(w, "межсайтовый запрос отклонён", http.StatusForbidden)
		return
	}
	var added []torrent.Ref
	if p.isAddRequest(r) {
		added = p.recordAdd(r)
	}
	p.rp.ServeHTTP(w, r)
	// Сообщаем в чат только после того, как запрос ушёл в qBittorrent.
	//
	// Порядок здесь важен дважды. Сообщение до проксирования рассказывало бы
	// о торренте, который qBittorrent может и не принять. И резидент ждал бы
	// ответа ровно столько, сколько отвечает Telegram.
	p.announceAdded(r, added)
}

// safeMethods — методы, которые сами по себе не меняют состояние.
var safeMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodOptions: true,
}

// crossSiteReason решает, пришёл ли запрос с чужой страницы.
//
// Проверяем два независимых признака: Origin (шлют все браузеры на небезопасных
// методах) и Sec-Fetch-Site (шлют современные). Верхнеуровневый переход с
// чужого сайта на сам интерфейс разрешаем — это обычная ссылка; к /api/ такой
// переход не пускаем, потому что часть эндпоинтов qBittorrent меняет состояние
// и по GET.
func (p *Proxy) crossSiteReason(r *http.Request) (string, bool) {
	self, _ := p.hosts.Origin(r)
	origin := r.Header.Get("Origin")
	// "null" — это неизвестный источник (песочница iframe, документ data:,
	// часть цепочек редиректов), а не свой. Исключать его не за что.
	foreignOrigin := origin != "" && origin != self

	site := r.Header.Get("Sec-Fetch-Site")
	foreignSite := site == "cross-site" || site == "same-site"

	if !safeMethods[r.Method] {
		if foreignOrigin {
			return "origin " + origin, true
		}
		if foreignSite {
			return "sec-fetch-site " + site, true
		}
		return "", false
	}
	if !foreignOrigin && !foreignSite {
		return "", false
	}
	// Безопасный метод с чужого сайта: интерфейс отдаём, API — нет.
	if strings.HasPrefix(p.strip(r.URL.Path), "/api/") {
		return "чужой источник для API", true
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode == "navigate" || mode == "" {
		return "", false
	}
	return "подресурсный запрос с чужого сайта", true
}

// apiNeedsProof закрывает лазейку для браузеров без Fetch-метаданных.
//
// Кросс-сайтовый GET не несёт Origin по определению, а Sec-Fetch-* шлют не
// все браузеры (Safari до 16.4). На таком браузере оба признака отсутствуют,
// и запрос к /api/ выглядел бы своим — при том, что часть эндпоинтов
// qBittorrent меняет состояние и по GET, а через setPreferences добирается до
// запуска программ на хосте. Поэтому в отсутствие метаданных требуем хотя бы
// свой Referer.
func (p *Proxy) apiNeedsProof(r *http.Request) (string, bool) {
	if !strings.HasPrefix(p.strip(r.URL.Path), "/api/") {
		return "", false
	}
	if r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Origin") != "" {
		return "", false // признаки есть, решение уже принято выше
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		// Заголовка нет вовсе — это программный клиент (curl из DEPLOY.md,
		// скрипт резидента). Требовать его значило бы сломать их ради
		// защиты, которую всё равно обходит referrer-policy: no-referrer.
		return "", false
	}
	self, _ := p.hosts.Origin(r)
	if !strings.HasPrefix(ref, self+"/") && ref != self {
		return "Referer " + ref, true
	}
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" || r.Header.Get("Sec-Fetch-Mode") == "" {
		return "", false
	}
	return "подресурсный запрос с чужого сайта", true
}

// hasDotSegment ищет сегменты "." и ".." в пути, в том числе закодированные.
//
// Закодированный слэш (%2f) отвергаем целиком: он делает разбор пути
// неоднозначным — мы видим один сегмент, а бэкенд после раскодирования два,
// и именно так строится обход префикса вида "..%2fverify". Легитимного
// применения у него в адресах qBittorrent нет.
func hasDotSegment(escapedPath string) bool {
	for _, seg := range strings.Split(escapedPath, "/") {
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			return true // разобрать не смогли — значит и пропускать не будем
		}
		if strings.ContainsAny(decoded, `/\`) {
			return true
		}
		if decoded == "." || decoded == ".." {
			return true
		}
	}
	return false
}

func (p *Proxy) isAddRequest(r *http.Request) bool {
	return r.Method == http.MethodPost && p.strip(r.URL.Path) == addPath
}

// recordAdd читает тело запроса, распознаёт торренты и берёт их под
// наблюдение, чтобы сообщить автору о конце загрузки.
//
// Истории добавлений шлюз не ведёт: её пишет бот в групповой чат, и вторая
// копия в базе только расходилась бы с первой. Здесь остаётся журнальная
// строка (по ней разбирают инциденты) и адресат будущего личного сообщения.
//
// Тело обязательно возвращается на место: резидент не должен пострадать
// от того, что мы подсмотрели его запрос. Любая ошибка разбора — только
// предупреждение в лог, запрос идёт дальше.
func (p *Proxy) recordAdd(r *http.Request) []torrent.Ref {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		p.log.Warn("добавление торрента без опознанного резидента")
		return nil
	}
	if r.Body == nil {
		return nil
	}

	// Место в очереди на разбор. Разбор держит тело целиком в памяти — до
	// MaxAddBodySize на запрос, — и без ограничения десяток одновременных
	// запросов от одного резидента положил бы весь шлюз, а с ним портал,
	// админку и остальные сервисы.
	//
	// Не дождавшись места, разбор пропускаем, а не ждём: ожидание держало бы
	// и горутину, и соединение, то есть меняло бы одну беду на другую.
	// Торрент при этом добавится как ни в чём не бывало — не будет только
	// сообщения в чат.
	select {
	case p.parseSlots <- struct{}{}:
		defer func() { <-p.parseSlots }()
	default:
		p.log.Warn("разбор добавления торрента пропущен: слишком много "+
			"одновременных добавлений", "user", claims.UID())
		return nil
	}

	original := r.Body
	// Читаем на байт больше лимита: так отличаем «влезло целиком» от «есть хвост».
	head, readErr := io.ReadAll(io.LimitReader(original, torrent.MaxAddBodySize+1))

	// Тело обязательно возвращается на место. Если прочитали не всё, склеиваем
	// прочитанное с остатком: усечь запрос резидента ради собственного
	// журнала — недопустимо. ContentLength не трогаем: он и так верен.
	restore := func() {
		if len(head) > torrent.MaxAddBodySize || readErr != nil {
			r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(head), original), closer: original}
			return
		}
		_ = original.Close()
		r.Body = io.NopCloser(bytes.NewReader(head))
	}
	defer restore()

	if readErr != nil {
		p.log.Warn("не удалось прочитать тело добавления торрента", "error", readErr)
		return nil
	}
	if len(head) > torrent.MaxAddBodySize {
		p.log.Warn("тело добавления торрента слишком велико, атрибуция пропущена",
			"size", len(head), "user", claims.UID())
		return nil
	}

	refs, err := torrent.ParseAddRequest(r.Header.Get("Content-Type"), head)
	if err != nil {
		p.log.Warn("не удалось разобрать добавление торрента", "error", err, "user", claims.UID())
	}
	watched := make([]Watched, 0, len(refs))
	for _, ref := range refs {
		// Магнит-ссылку в журнал не пишем: она содержит всё нужное для
		// скачивания, а журнал читают шире, чем чат.
		p.log.Info("резидент поставил торрент на загрузку",
			"user", claims.UID(), "username", claims.Username,
			"torrent", ref.Name, "source", ref.Source)
		watched = append(watched, Watched{
			InfoHash:   ref.InfoHash,
			Name:       ref.Name,
			TelegramID: claims.TelegramID,
			Username:   claims.Username,
		})
	}
	// Воркер сам отсеет то, за чем следить нечем (ссылка на .torrent, у
	// которой хеша ещё нет), и сам поднимется, если ещё не работает.
	if p.track != nil && len(watched) > 0 {
		p.track.Track(watched...)
	}
	return refs
}

// announceAdded сообщает в чат о добавленных торрентах.
//
// Отправка идёт в отдельной горутине и уже после того, как запрос ушёл в
// qBittorrent: чат не должен ни задерживать загрузку, ни влиять на ответ
// резиденту. Контекст отвязан от запроса — браузер обычно уходит со
// страницы сразу после добавления, и с его контекстом отправка обрывалась бы
// на полпути.
//
// Число сообщений ограничено: за один запрос можно добавить до
// torrent.MaxRefs ссылок, и отправлять по сообщению на каждую значило бы
// упереться в ограничения Telegram и залить чат.
func (p *Proxy) announceAdded(r *http.Request, refs []torrent.Ref) {
	if p.announce == nil || len(refs) == 0 {
		return
	}
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return
	}
	if len(refs) > maxAnnounced {
		p.log.Warn("за один запрос добавлено больше торрентов, чем сообщается в чат",
			"added", len(refs), "announced", maxAnnounced,
			"user", claims.UID())
		refs = refs[:maxAnnounced]
	}

	user, display, uid := claims.Username, claims.DisplayName(), claims.UID()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), announceTimeout)
		defer cancel()
		for _, ref := range refs {
			err := p.announce.Notify(ctx, tgnotify.Event{
				Username:    user,
				DisplayName: display,
				TorrentName: ref.Name,
				Magnet:      magnetOf(ref),
			})
			if err != nil {
				// Пробуем остальные: сбой на одном торренте — обычно его
				// собственная беда (слишком длинное имя, битая ссылка), и
				// молча терять из-за него всю пачку незачем.
				p.log.Warn("не удалось сообщить в чат о торренте",
					"error", err, "user", uid, "torrent", ref.Name)
				continue
			}
		}
	}()
}

// announceTimeout ограничивает отправку всей пачки в чат.
const announceTimeout = 30 * time.Second

// maxAnnounced — сколько торрентов из одного запроса попадёт в чат.
const maxAnnounced = 5

// magnetOf возвращает магнит-ссылку для сообщения.
//
// Для magnet-источника берём исходную ссылку целиком — в ней есть трекеры.
// Для .torrent-файла собираем минимальную ссылку из infohash: этого хватает,
// чтобы клиент нашёл раздачу по DHT. Для ссылки на .torrent по http хеш ещё
// неизвестен, и ссылки не будет вовсе.
func magnetOf(ref torrent.Ref) string {
	if ref.Source == torrent.SourceMagnet && strings.HasPrefix(ref.Raw, "magnet:") {
		return ref.Raw
	}
	if ref.InfoHash == "" {
		return ""
	}
	link := "magnet:?xt=urn:btih:" + ref.InfoHash
	if ref.Name != "" {
		link += "&dn=" + url.QueryEscape(ref.Name)
	}
	return link
}

// readCloser склеивает поток чтения с закрытием исходного тела запроса.
type readCloser struct {
	io.Reader
	closer io.Closer
}

func (rc readCloser) Close() error { return rc.closer.Close() }

// rewrite готовит исходящий запрос к qBittorrent.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	out := pr.Out
	pr.SetXForwarded() // X-Forwarded-For/Proto/Host для qBittorrent
	// Схему берём из заголовков исходного запроса: SetXForwarded смотрит на
	// r.In.TLS, а TLS снимает Traefik, и без этой строки резидент, пришедший
	// по https, объявляется qBittorrent как пришедший по http.
	pr.Out.Header.Set("X-Forwarded-Proto", auth.RequestScheme(pr.In))

	// X-Forwarded-Host снимаем всегда, иначе весь интерфейс отвечает 401.
	//
	// Свой «целевой источник» для проверки CSRF qBittorrent строит из
	// X-Forwarded-Host, а не из Host, — и делает это даже при выключенной
	// поддержке реверс-прокси. Ниже мы подставляем Referer и Origin, равные
	// внутреннему адресу qBittorrent, так что с публичным именем в XFH
	// сравнение заведомо не сходится. В его журнале это видно дословно:
	// «Оригинальный и целевой заголовки не совпадают! Заголовок источника:
	// http://192.168.8.43:8081. Целевой источник: localhost». Пустое значение
	// тоже не спасает — целевой источник просто становится пустым.
	//
	// Подставлять сюда его собственный адрес незачем: бэкенд мы и так
	// адресуем внутренним именем (out.Host ниже), а редиректы правим сами.
	out.Header.Del("X-Forwarded-Host")

	// В режиме bypass qBittorrent доверяет нашему адресу и берёт клиента из
	// X-Forwarded-For. Оставив там IP браузера, мы заставили бы оператора
	// вносить в whitelist подсети резидентов вместо подсети шлюза — то
	// есть открыть qBittorrent всей локальной сети без пароля.
	//
	// В режиме session адрес клиента qBittorrent нужен для журнала, но
	// только тот, который мы видим сами, — см. clientIP ниже: цепочку из
	// заголовка сюда пускать нельзя.
	if p.client.UsesSession() {
		out.Header.Set("X-Forwarded-For", clientIP(pr.In))
	} else {
		out.Header.Del("X-Forwarded-For")
	}

	out.URL.Scheme = p.target.Scheme
	out.URL.Host = p.target.Host
	out.URL.Path = p.target.Path + p.strip(pr.In.URL.Path)
	out.Host = p.target.Host

	// Куки браузера сюда попадать не должны: среди них лежит JWT резидента,
	// а qBittorrent для него — посторонний сервис.
	out.Header.Del("Cookie")
	auth.StripIdentityHeaders(out.Header)

	if sid, err := p.client.SID(pr.In.Context()); err == nil && sid != "" {
		out.AddCookie(&http.Cookie{Name: "SID", Value: sid})
	} else if err != nil {
		p.log.Error("не удалось получить сессию qBittorrent", "error", err)
	}

	// qBittorrent сверяет Referer/Origin с собственным адресом (защита от CSRF),
	// а браузер пришлёт адрес портала.
	origin := p.target.Scheme + "://" + p.target.Host
	out.Header.Set("Referer", origin)
	out.Header.Set("Origin", origin)
}

// clientIP возвращает адрес того, кто подключился к шлюзу.
//
// Берётся из RemoteAddr, а не из заголовков: заголовки пишет клиент.
// Намеренно берётся только RemoteAddr.
//
// Взять адрес из X-Forwarded-For заманчиво — тогда в журнале qBittorrent были
// бы настоящие адреса резидентов, а не один адрес Traefik. Но Traefik
// ДОПИСЫВАЕТ настоящий адрес в конец пришедшей цепочки, а не заменяет её:
// первый элемент по-прежнему задаёт клиент. qBittorrent с включённой
// поддержкой реверс-прокси читает как раз первый — и резидент смог бы
// подставить любой чужой адрес в бан или в whitelist. Худший журнал дешевле.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// strip убирает публичный префикс, оставляя путь, понятный qBittorrent.
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

// modifyResponse чинит ответы, которые «не знают» о префиксе.
func (p *Proxy) modifyResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusForbidden {
		// Скорее всего протухла сессия — следующий запрос перелогинится.
		p.client.Invalidate()
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		resp.Header.Set("Location", relocate(loc, p.basePath, p.target.Host))
	}
	// Cookie SID принадлежит служебной сессии шлюза, отдавать её браузеру
	// нельзя: иначе резидент получит прямой доступ к qBittorrent в обход
	// проверки авторизации.
	resp.Header.Del("Set-Cookie")
	return nil
}

func (p *Proxy) handleError(w http.ResponseWriter, r *http.Request, err error) {
	p.log.Error("qBittorrent недоступен", "error", err, "path", r.URL.Path)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, "qBittorrent недоступен, попробуйте позже\n")
}

// relocate приводит Location из ответа сервиса к адресу шлюза.
//
// Сервис о префиксе не знает и отвечает, например, «Location: /web/» на
// запрос корня. Хуже другой случай: с настроенной поддержкой обратного
// прокси сервис отдаёт абсолютный адрес со своим внутренним хостом
// («http://192.168.8.43:8096/web/»). Резидент из интернета такого хоста не
// увидит вовсе, а сам адрес выдаёт устройство локальной сети — поэтому
// внутренний хост заменяем на префикс шлюза.
func relocate(loc, basePath, upstreamHost string) string {
	if loc == "" || basePath == "" {
		return loc
	}
	if strings.HasPrefix(loc, "/") {
		if strings.HasPrefix(loc, basePath+"/") || loc == basePath {
			return loc
		}
		return basePath + loc
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" || u.Host != upstreamHost {
		// Чужой хост не трогаем: это редирект наружу, и подменять его нельзя.
		return loc
	}
	u.Scheme, u.Host = "", ""
	rest := u.String()
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	if strings.HasPrefix(rest, basePath+"/") || rest == basePath {
		return rest
	}
	return basePath + rest
}
