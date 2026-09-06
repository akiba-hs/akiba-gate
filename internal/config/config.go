// Пакет config собирает конфигурацию сервиса из переменных окружения.
//
// Принцип: сервис либо стартует с полностью валидной конфигурацией, либо
// падает при запуске с понятным сообщением. Тихих дефолтов для секретов нет —
// пустой секрет SSO не должен «случайно» уехать в прод.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// QbitAuthMode задаёт способ, которым шлюз авторизуется в qBittorrent.
type QbitAuthMode string

const (
	// QbitAuthSession — шлюз сам логинится в WebUI служебной учёткой и
	// подставляет cookie SID в проксируемые запросы. qBittorrent при этом
	// остаётся защищённым паролем. Режим по умолчанию.
	QbitAuthSession QbitAuthMode = "session"
	// QbitAuthBypass — вход в qBittorrent отключён для подсети шлюза
	// («Bypass authentication for clients in whitelisted IP subnets»).
	// Проще в настройке, но безопасность целиком держится на Traefik.
	QbitAuthBypass QbitAuthMode = "bypass"
)

// Config — полная конфигурация akiba-gate.
type Config struct {
	ListenAddr string        // адрес HTTP-сервера, например ":8080"
	LogLevel   string        // debug|info|warn|error
	Timeout    time.Duration // таймаут исходящих HTTP-запросов к сервисам

	// Авторизация
	JWTPublicKeyPEM []byte // публичный ключ RSA для проверки подписи токенов auth-service
	AuthURL         *url.URL
	PublicBaseURL   *url.URL // https://inside.akiba.space
	// AuthReturnBaseURL — схема и хост адреса, на который auth-service
	// возвращает человека после входа. По умолчанию совпадает с
	// PublicBaseURL и задавать его не нужно. Отдельная настройка существует
	// потому, что auth-service проверяет redirect_uri как
	// netloc.endswith(".akiba.space"), а netloc включает порт: портал,
	// открытый на нестандартном порту, иначе получает 400 Invalid redirect_uri.
	AuthReturnBaseURL *url.URL
	// ExtraHosts — дополнительные имена, под которыми портал считается своим.
	// По ним проверяется Origin запросов к qBittorrent и строится адрес
	// Jellyfin для localStorage, поэтому имя должно совпадать с адресной
	// строкой дословно, вместе с портом.
	ExtraHosts      []string
	CookieName      string
	RequireResident bool

	// Jellyfin
	JellyfinInternalURL *url.URL
	JellyfinBasePath    string // публичный префикс, например "/jellyfin"
	JellyfinUser        string
	JellyfinPassword    string

	// Nextcloud
	NextcloudPublicURL *url.URL
	// NextcloudSSOPath — адрес приложения-адаптера внутри Nextcloud, куда
	// уходит браузер с одноразовым кодом.
	NextcloudSSOPath string
	// NextcloudSSOSecret — общий секрет между шлюзом и приложением-адаптером.
	// Им приложение доказывает, что имеет право обменять код на личность:
	// без него украденный код бесполезен.
	NextcloudSSOSecret string
	// NextcloudSSOBindIP включает привязку одноразового кода к адресу
	// браузера. Защищает от того, что перехваченный код откроют из другого
	// места; выключается, если шлюз и Nextcloud видят клиента под разными
	// адресами (NAT между ними).
	NextcloudSSOBindIP bool

	// qBittorrent
	QbitInternalURL *url.URL
	QbitBasePath    string // публичный префикс, например "/qbittorrent"
	QbitAuthMode    QbitAuthMode
	QbitUser        string
	QbitPassword    string

	// AdminTelegramID — Telegram-ID изначального администратора. У него
	// всегда есть доступ ко всем сервисам, и снять этот доступ нельзя ничем,
	// кроме правки конфигурации: иначе второй администратор мог бы запереть
	// первого снаружи собственной системы.
	AdminTelegramID string

	// Состояние и уведомления
	DBPath string
	// TelegramToken и TelegramChatID включают бота, сообщающего о новых
	// торрентах. Оба необязательны: без них шлюз работает как прежде, просто
	// молча. Отдельного флага «включено» нет намеренно — он позволял бы
	// включить бота, забыв заполнить токен, и потом искать причину молчания.
	TelegramToken  string
	TelegramChatID string

	// Тексты интерфейса
	I18nPath string
	I18nTTL  time.Duration

	// SOCKS5 для исходящих запросов в Telegram (аватарки и бот).
	// Пустой адрес означает прямой выход.
	SocksAddress  string
	SocksUser     string
	SocksPassword string
}

// Load читает конфигурацию из окружения и валидирует её целиком, собирая все
// ошибки сразу: чинить конфиг по одной опечатке за перезапуск — мучение.
func Load(getenv func(string) string) (*Config, error) {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	cfg := &Config{
		ListenAddr:         def(getenv("LISTEN_ADDR"), ":8080"),
		LogLevel:           def(getenv("LOG_LEVEL"), "info"),
		CookieName:         def(getenv("AUTH_COOKIE_NAME"), "token"),
		JellyfinBasePath:   normalizePrefix(def(getenv("JELLYFIN_BASE_PATH"), "/jellyfin")),
		QbitBasePath:       normalizePrefix(def(getenv("QBITTORRENT_BASE_PATH"), "/qbittorrent")),
		NextcloudSSOPath:   def(getenv("NEXTCLOUD_SSO_PATH"), "/index.php/apps/akibasso/login"),
		NextcloudSSOSecret: getenv("NEXTCLOUD_SSO_SECRET"),
		AdminTelegramID:    strings.TrimSpace(getenv("ADMIN_TELEGRAM_ID")),
		DBPath:             def(getenv("DB_PATH"), "/var/lib/akiba-gate/gate.db"),
		JellyfinUser:       getenv("JELLYFIN_USER"),
		JellyfinPassword:   getenv("JELLYFIN_PASSWORD"),
		QbitUser:           getenv("QBITTORRENT_USER"),
		QbitPassword:       getenv("QBITTORRENT_PASSWORD"),
		TelegramToken:      getenv("TELEGRAM_BOT_TOKEN"),
		TelegramChatID:     getenv("TELEGRAM_CHAT_ID"),
		I18nPath:           def(getenv("I18N_PATH"), "/etc/akiba-gate/i18n.ru.json"),
		SocksAddress:       getenv("SOCKS5_PROXY"),
		SocksUser:          getenv("SOCKS5_USER"),
		SocksPassword:      getenv("SOCKS5_PASSWORD"),
	}

	var err error
	if cfg.RequireResident, err = parseBool(getenv("REQUIRE_RESIDENT"), true); err != nil {
		fail("REQUIRE_RESIDENT: %w", err)
	}
	if cfg.NextcloudSSOBindIP, err = parseBool(getenv("NEXTCLOUD_SSO_BIND_IP"), true); err != nil {
		fail("NEXTCLOUD_SSO_BIND_IP: %w", err)
	}
	// Уровень журнала проверяем здесь, а не при создании логгера: там
	// опечатка молча превращалась бы в info, и оператор, поставивший
	// LOG_LEVEL=verbose ради отладки, искал бы пропавшие строки где угодно,
	// только не в своей же переменной.
	if lvl := getenv("LOG_LEVEL"); lvl != "" {
		var parsed slog.Level
		if err := parsed.UnmarshalText([]byte(lvl)); err != nil {
			fail("LOG_LEVEL: ожидалось debug, info, warn или error, получено %q", lvl)
		}
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		fail("LISTEN_ADDR: ожидался адрес вида \":8080\" или \"127.0.0.1:8080\": %w", err)
	}

	timeout, terr := parseDuration(getenv("HTTP_TIMEOUT"), 15*time.Second)
	if terr != nil {
		fail("HTTP_TIMEOUT: %w", terr)
	}
	// Ноль в http.Client означает «без срока»: Jellyfin, qBittorrent и
	// Telegram зависали бы навсегда, а отрицательное значение роняло бы
	// каждый запрос мгновенно. И то и другое выглядит как поломка сети, а
	// не как опечатка в конфигурации.
	if terr == nil && timeout <= 0 {
		fail("HTTP_TIMEOUT: ожидался положительный срок, например 15s")
	}
	cfg.Timeout = timeout

	ttl, terr := parseDuration(getenv("I18N_TTL"), time.Minute)
	if terr != nil {
		fail("I18N_TTL: %w", terr)
	}
	if ttl <= 0 {
		fail("I18N_TTL: ожидался положительный срок, например 1m")
	}
	cfg.I18nTTL = ttl

	// Адрес прокси проверяем сразу: опечатка в нём обернулась бы отказом
	// аватарок и молчанием бота уже в работе, а не при запуске.
	if cfg.SocksAddress != "" {
		if _, _, err := net.SplitHostPort(cfg.SocksAddress); err != nil {
			fail("SOCKS5_PROXY: ожидался адрес вида \"127.0.0.1:1080\": %w", err)
		}
	}

	// Публичный ключ: либо PEM прямо в переменной, либо путь к файлу.
	switch {
	case getenv("JWT_PUBLIC_KEY_PATH") != "":
		data, err := os.ReadFile(getenv("JWT_PUBLIC_KEY_PATH"))
		if err != nil {
			fail("JWT_PUBLIC_KEY_PATH: %w", err)
		}
		cfg.JWTPublicKeyPEM = data
	case getenv("JWT_PUBLIC_KEY") != "":
		// В окружении удобно хранить PEM одной строкой с экранированными \n.
		cfg.JWTPublicKeyPEM = []byte(strings.ReplaceAll(getenv("JWT_PUBLIC_KEY"), `\n`, "\n"))
	default:
		fail("нужен JWT_PUBLIC_KEY или JWT_PUBLIC_KEY_PATH")
	}

	cfg.AuthURL = mustURL(getenv("AUTH_URL"), "AUTH_URL", &errs)
	cfg.PublicBaseURL = mustURL(getenv("PUBLIC_BASE_URL"), "PUBLIC_BASE_URL", &errs)
	cfg.ExtraHosts = splitList(getenv("ALLOWED_HOSTS"))
	if raw := getenv("AUTH_RETURN_BASE_URL"); raw != "" {
		cfg.AuthReturnBaseURL = mustURL(raw, "AUTH_RETURN_BASE_URL", &errs)
	} else {
		cfg.AuthReturnBaseURL = cfg.PublicBaseURL
	}
	cfg.JellyfinInternalURL = mustURL(getenv("JELLYFIN_INTERNAL_URL"), "JELLYFIN_INTERNAL_URL", &errs)
	cfg.NextcloudPublicURL = mustURL(getenv("NEXTCLOUD_PUBLIC_URL"), "NEXTCLOUD_PUBLIC_URL", &errs)
	cfg.QbitInternalURL = mustURL(getenv("QBITTORRENT_INTERNAL_URL"), "QBITTORRENT_INTERNAL_URL", &errs)

	if cfg.JellyfinUser == "" || cfg.JellyfinPassword == "" {
		fail("нужны JELLYFIN_USER и JELLYFIN_PASSWORD (общая учётка резидентов)")
	}
	// Секрет SSO обязателен: без него приложение-адаптер в Nextcloud не
	// сможет обменять код на личность, и вход просто не заработает. Короткий
	// секрет отвергаем сразу — его подбор снимает всю защиту обмена.
	if len(cfg.NextcloudSSOSecret) < minSSOSecretLen {
		fail("NEXTCLOUD_SSO_SECRET: нужен секрет длиной не меньше %d символов "+
			"(сгенерируйте: openssl rand -base64 32)", minSSOSecretLen)
	}
	if !strings.HasPrefix(cfg.NextcloudSSOPath, "/") {
		fail("NEXTCLOUD_SSO_PATH: путь должен начинаться со слэша, получено %q", cfg.NextcloudSSOPath)
	}
	// Без администратора админка недоступна никому, и раздать права было бы
	// некому: система запиралась бы на себе при первом же запуске.
	if cfg.AdminTelegramID == "" {
		fail("ADMIN_TELEGRAM_ID: не задан; без него некому раздавать доступ к сервисам")
	} else if !isDigits(cfg.AdminTelegramID) {
		fail("ADMIN_TELEGRAM_ID: ожидался числовой Telegram-ID, получено %q", cfg.AdminTelegramID)
	}

	// Пустой префикс — это "/" в исходной переменной. Маршрут для него не
	// регистрируется, сервис молча отвечает 404 через портал, и оператор
	// ищет причину где угодно, только не в конфигурации.
	if cfg.JellyfinBasePath == "" {
		fail("JELLYFIN_BASE_PATH: нужен непустой префикс, например /jellyfin")
	}
	if cfg.QbitBasePath == "" {
		fail("QBITTORRENT_BASE_PATH: нужен непустой префикс, например /qbittorrent")
	}

	cfg.QbitAuthMode = QbitAuthMode(def(getenv("QBITTORRENT_AUTH_MODE"), string(QbitAuthSession)))
	switch cfg.QbitAuthMode {
	case QbitAuthSession:
		if cfg.QbitUser == "" || cfg.QbitPassword == "" {
			fail("режим QBITTORRENT_AUTH_MODE=session требует QBITTORRENT_USER и QBITTORRENT_PASSWORD")
		}
	case QbitAuthBypass:
		// Логин не нужен: qBittorrent пускает подсеть шлюза без пароля.
	default:
		fail("QBITTORRENT_AUTH_MODE: ожидалось %q или %q, получено %q",
			QbitAuthSession, QbitAuthBypass, cfg.QbitAuthMode)
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("некорректная конфигурация:\n  - %s",
			strings.Join(errStrings(errs), "\n  - "))
	}
	return cfg, nil
}

// minSSOSecretLen — нижняя граница длины общего секрета с приложением
// Nextcloud. 32 символа — это вывод `openssl rand -base64 24`; всё, что
// короче, скорее опечатка или «временное значение», чем секрет.
const minSSOSecretLen = 32

// isDigits сообщает, состоит ли строка только из цифр и непуста.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func mustURL(raw, name string, errs *[]error) *url.URL {
	if raw == "" {
		*errs = append(*errs, fmt.Errorf("%s: не задан", name))
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", name, err))
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		*errs = append(*errs, fmt.Errorf("%s: ожидалась схема http/https, получено %q", name, u.Scheme))
		return nil
	}
	if u.Host == "" {
		*errs = append(*errs, fmt.Errorf("%s: не указан хост", name))
		return nil
	}
	// Хвостовой слэш только мешает при склейке путей.
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u
}

// normalizePrefix приводит префикс пути к виду "/name" (без хвостового слэша).
func normalizePrefix(p string) string {
	p = "/" + strings.Trim(p, "/")
	if p == "/" {
		return ""
	}
	return p
}

// splitList разбирает список через запятую, пробел или точку с запятой.
// Пустые элементы отбрасываются — иначе хвостовая запятая давала бы пустое
// имя хоста, которое HostPolicy честно отвергнет, а оператор будет искать
// причину в другом месте.
func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func def(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// parseBool не прощает опечаток.
//
// Тихий откат на значение по умолчанию — худший из вариантов: оператор пишет
// REQUIRE_RESIDENT=yes, видит успешный старт и уверен, что настроил политику
// доступа, хотя она осталась прежней.
func parseBool(v string, fallback bool) (bool, error) {
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("ожидалось true или false, получено %q", v)
	}
	return b, nil
}

func parseDuration(v string, fallback time.Duration) (time.Duration, error) {
	if v == "" {
		return fallback, nil
	}
	return time.ParseDuration(v)
}

func errStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Error())
	}
	return out
}
