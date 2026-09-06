package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/config"
)

// validEnv — минимально полный набор переменных.
func validEnv() map[string]string {
	return map[string]string{
		"JWT_PUBLIC_KEY":           "-----BEGIN PUBLIC KEY-----\\nAAA\\n-----END PUBLIC KEY-----",
		"AUTH_URL":                 "https://auth.akiba.space/",
		"PUBLIC_BASE_URL":          "https://inside.akiba.space",
		"JELLYFIN_INTERNAL_URL":    "http://jellyfin:8096",
		"JELLYFIN_USER":            "residents",
		"JELLYFIN_PASSWORD":        "jf-pass",
		"NEXTCLOUD_PUBLIC_URL":     "https://nextcloud.akiba.space",
		"NEXTCLOUD_SSO_SECRET":     "0123456789012345678901234567890123456789",
		"ADMIN_TELEGRAM_ID":        "270369579",
		"QBITTORRENT_INTERNAL_URL": "http://qbittorrent:8080",
		"QBITTORRENT_USER":         "gate",
		"QBITTORRENT_PASSWORD":     "qb-pass",
	}
}

func loader(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func TestLoadValidConfig(t *testing.T) {
	cfg, err := config.Load(loader(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if !cfg.RequireResident {
		t.Fatal("по умолчанию доступ должен быть только для резидентов")
	}
	if cfg.TelegramToken != "" || cfg.TelegramChatID != "" {
		t.Fatal("бот по умолчанию не настроен")
	}
	if cfg.I18nTTL != time.Minute {
		t.Fatalf("срок кэша текстов = %v, ожидалась минута", cfg.I18nTTL)
	}
	if cfg.QbitAuthMode != config.QbitAuthSession {
		t.Fatalf("режим qBittorrent = %q", cfg.QbitAuthMode)
	}
	if cfg.QbitBasePath != "/qbittorrent" || cfg.JellyfinBasePath != "/jellyfin" {
		t.Fatalf("префиксы: %q, %q", cfg.QbitBasePath, cfg.JellyfinBasePath)
	}
	if cfg.NextcloudSSOPath != "/index.php/apps/akibasso/login" {
		t.Fatalf("путь приложения Nextcloud = %q", cfg.NextcloudSSOPath)
	}
	// Привязка кода к адресу браузера включена по умолчанию: выключать
	// защиту молча нельзя, её выключают осознанно.
	if !cfg.NextcloudSSOBindIP {
		t.Fatal("привязка кода к адресу клиента должна быть включена по умолчанию")
	}
	if cfg.AdminTelegramID != "270369579" {
		t.Fatalf("администратор = %q", cfg.AdminTelegramID)
	}
	// Экранированные \n в переменной окружения должны превращаться в переносы.
	if !strings.Contains(string(cfg.JWTPublicKeyPEM), "\n") {
		t.Fatal("переносы строк в PEM не восстановлены")
	}
	// Хвостовой слэш в URL мешает склейке путей и должен сниматься.
	if strings.HasSuffix(cfg.AuthURL.Path, "/") {
		t.Fatalf("AuthURL.Path = %q", cfg.AuthURL.Path)
	}
}

func TestLoadReportsAllProblemsAtOnce(t *testing.T) {
	// Чинить конфиг по одной ошибке за перезапуск контейнера — мучение,
	// поэтому Load обязан собрать все проблемы сразу.
	_, err := config.Load(loader(map[string]string{}))
	if err == nil {
		t.Fatal("пустое окружение принято")
	}
	msg := err.Error()
	for _, want := range []string{"JWT_PUBLIC_KEY", "AUTH_URL", "PUBLIC_BASE_URL",
		"JELLYFIN_USER", "QBITTORRENT_INTERNAL_URL"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("в сообщении нет %q:\n%s", want, msg)
		}
	}
}

// Без секрета приложение-адаптер не сможет обменять код, и вход в Nextcloud
// просто не заработает — молча. Поэтому это ошибка запуска.
func TestLoadRejectsMissingSSOSecret(t *testing.T) {
	env := validEnv()
	env["NEXTCLOUD_SSO_SECRET"] = ""
	if _, err := config.Load(loader(env)); err == nil {
		t.Fatal("пустой NEXTCLOUD_SSO_SECRET принят")
	}
}

// Короткий секрет подбирается, а значит не защищает обмен кода ни от чего.
func TestLoadRejectsShortSSOSecret(t *testing.T) {
	env := validEnv()
	env["NEXTCLOUD_SSO_SECRET"] = "коротко"
	if _, err := config.Load(loader(env)); err == nil {
		t.Fatal("короткий NEXTCLOUD_SSO_SECRET принят")
	}
}

// Без администратора раздавать доступ некому: система заперлась бы на себе.
func TestLoadRequiresAdmin(t *testing.T) {
	env := validEnv()
	env["ADMIN_TELEGRAM_ID"] = ""
	_, err := config.Load(loader(env))
	if err == nil {
		t.Fatal("пустой ADMIN_TELEGRAM_ID принят")
	}
	if !strings.Contains(err.Error(), "ADMIN_TELEGRAM_ID") {
		t.Fatalf("в сообщении нет причины:\n%s", err)
	}
}

// Telegram-ID — число. Ник или @-форма здесь означают опечатку, из-за которой
// администратором не станет никто, и заметить это можно будет только по тому,
// что админка недоступна.
func TestLoadRejectsNonNumericAdmin(t *testing.T) {
	env := validEnv()
	env["ADMIN_TELEGRAM_ID"] = "@ilvesbogdan"
	if _, err := config.Load(loader(env)); err == nil {
		t.Fatal("нечисловой ADMIN_TELEGRAM_ID принят")
	}
}

func TestLoadRejectsBadURLs(t *testing.T) {
	cases := map[string]string{
		"без схемы":   "inside.akiba.space",
		"чужая схема": "ftp://inside.akiba.space",
		"без хоста":   "https://",
		"мусор":       "://",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			env := validEnv()
			env["PUBLIC_BASE_URL"] = value
			if _, err := config.Load(loader(env)); err == nil {
				t.Fatalf("URL %q принят", value)
			}
		})
	}
}

func TestLoadQbitBypassModeNeedsNoCredentials(t *testing.T) {
	env := validEnv()
	env["QBITTORRENT_AUTH_MODE"] = "bypass"
	delete(env, "QBITTORRENT_USER")
	delete(env, "QBITTORRENT_PASSWORD")

	cfg, err := config.Load(loader(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QbitAuthMode != config.QbitAuthBypass {
		t.Fatalf("режим = %q", cfg.QbitAuthMode)
	}
}

func TestLoadSessionModeRequiresCredentials(t *testing.T) {
	env := validEnv()
	delete(env, "QBITTORRENT_PASSWORD")

	_, err := config.Load(loader(env))
	if err == nil || !strings.Contains(err.Error(), "QBITTORRENT_PASSWORD") {
		t.Fatalf("ожидалась ошибка про пароль, получено %v", err)
	}
}

func TestLoadRejectsUnknownQbitMode(t *testing.T) {
	env := validEnv()
	env["QBITTORRENT_AUTH_MODE"] = "magic"
	if _, err := config.Load(loader(env)); err == nil {
		t.Fatal("неизвестный режим принят")
	}
}

// Бот включается наличием токена и чата, отдельного флага нет: он позволял бы
// включить бота с пустым токеном и потом искать причину молчания.
func TestLoadEnablesBotByCredentials(t *testing.T) {
	env := validEnv()
	env["TELEGRAM_BOT_TOKEN"] = "123:abc"
	env["TELEGRAM_CHAT_ID"] = "-1001"
	cfg, err := config.Load(loader(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TelegramToken != "123:abc" || cfg.TelegramChatID != "-1001" {
		t.Fatalf("данные бота не прочитаны: %q %q", cfg.TelegramToken, cfg.TelegramChatID)
	}
}

func TestLoadReadsPublicKeyFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), 0o600); err != nil {
		t.Fatalf("запись файла: %v", err)
	}
	env := validEnv()
	delete(env, "JWT_PUBLIC_KEY")
	env["JWT_PUBLIC_KEY_PATH"] = path

	cfg, err := config.Load(loader(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.Contains(string(cfg.JWTPublicKeyPEM), "BEGIN PUBLIC KEY") {
		t.Fatal("ключ из файла не прочитан")
	}
}

func TestLoadFailsOnMissingKeyFile(t *testing.T) {
	env := validEnv()
	delete(env, "JWT_PUBLIC_KEY")
	env["JWT_PUBLIC_KEY_PATH"] = filepath.Join(t.TempDir(), "нет-такого.pem")

	if _, err := config.Load(loader(env)); err == nil {
		t.Fatal("отсутствующий файл ключа принят")
	}
}

func TestLoadParsesTimeoutAndNormalizesPrefixes(t *testing.T) {
	env := validEnv()
	env["HTTP_TIMEOUT"] = "42s"
	env["QBITTORRENT_BASE_PATH"] = "qb/"
	env["JELLYFIN_BASE_PATH"] = "/media/"

	cfg, err := config.Load(loader(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 42*time.Second {
		t.Fatalf("Timeout = %v", cfg.Timeout)
	}
	if cfg.QbitBasePath != "/qb" || cfg.JellyfinBasePath != "/media" {
		t.Fatalf("префиксы: %q, %q", cfg.QbitBasePath, cfg.JellyfinBasePath)
	}
}

func TestLoadRejectsBadTimeout(t *testing.T) {
	env := validEnv()
	env["HTTP_TIMEOUT"] = "быстро"
	if _, err := config.Load(loader(env)); err == nil {
		t.Fatal("некорректный тайм-аут принят")
	}
}

func TestLoadBypassModeIgnoresCredentials(t *testing.T) {
	// Учётные данные могут остаться в .env после смены режима — конфигурация
	// должна их принять, а решение о логине принимается по режиму.
	env := validEnv()
	env["QBITTORRENT_AUTH_MODE"] = "bypass"

	cfg, err := config.Load(loader(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QbitAuthMode != config.QbitAuthBypass {
		t.Fatalf("режим = %q", cfg.QbitAuthMode)
	}
}

// Тихий откат на значение по умолчанию — худший вариант: оператор пишет
// REQUIRE_RESIDENT=yes, видит успешный старт и уверен, что настроил политику.
func TestLoadRejectsMalformedBooleans(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"REQUIRE_RESIDENT", "yes"},
		{"REQUIRE_RESIDENT", "нет"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			env := validEnv()
			env[tc.key] = tc.value
			_, err := config.Load(loader(env))
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("ожидалась ошибка про %s, получено %v", tc.key, err)
			}
		})
	}
}

// Невалидный LISTEN_ADDR должен ловиться на старте: иначе ошибка всплывает
// уже при ListenAndServe, на аварийном пути завершения.
func TestLoadRejectsBadListenAddr(t *testing.T) {
	for _, addr := range []string{"8080", "не адрес", "127.0.0.1"} {
		env := validEnv()
		env["LISTEN_ADDR"] = addr
		if _, err := config.Load(loader(env)); err == nil {
			t.Fatalf("адрес %q принят", addr)
		}
	}
}

func TestLoadAcceptsValidListenAddrForms(t *testing.T) {
	for _, addr := range []string{":8080", "127.0.0.1:8080", "0.0.0.0:9000"} {
		env := validEnv()
		env["LISTEN_ADDR"] = addr
		if _, err := config.Load(loader(env)); err != nil {
			t.Fatalf("адрес %q отклонён: %v", addr, err)
		}
	}
}

// ALLOWED_HOSTS и AUTH_RETURN_BASE_URL появились из-за реальной поломки:
// портал открывали по адресу с портом, а auth-service такой redirect_uri
// отвергает с 400. Разделитель терпим любой из привычных.
func TestLoadParsesAllowedHostsAndReturnBase(t *testing.T) {
	env := validEnv()
	env["ALLOWED_HOSTS"] = "inside.akiba.space:8080, 192.168.8.82 ;inside.akiba.space,"
	env["AUTH_RETURN_BASE_URL"] = "http://inside.akiba.space"

	cfg, err := config.Load(loader(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"inside.akiba.space:8080", "192.168.8.82", "inside.akiba.space"}
	if len(cfg.ExtraHosts) != len(want) {
		t.Fatalf("ExtraHosts = %q, ожидалось %q", cfg.ExtraHosts, want)
	}
	for i := range want {
		if cfg.ExtraHosts[i] != want[i] {
			t.Fatalf("ExtraHosts = %q, ожидалось %q", cfg.ExtraHosts, want)
		}
	}
	if cfg.AuthReturnBaseURL.Host != "inside.akiba.space" {
		t.Fatalf("AuthReturnBaseURL = %q", cfg.AuthReturnBaseURL)
	}
}

// Без AUTH_RETURN_BASE_URL адрес возврата равен публичному — поведение
// по умолчанию не меняется.
func TestLoadDefaultsReturnBaseToPublicURL(t *testing.T) {
	cfg, err := config.Load(loader(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthReturnBaseURL != cfg.PublicBaseURL {
		t.Fatalf("AuthReturnBaseURL = %v, ожидался PublicBaseURL = %v",
			cfg.AuthReturnBaseURL, cfg.PublicBaseURL)
	}
	if cfg.ExtraHosts != nil {
		t.Fatalf("ExtraHosts = %q, ожидался пустой список", cfg.ExtraHosts)
	}
}

// Префикс "/" превращается в пустую строку, маршрут для него не
// регистрируется, и сервис молча отвечает 404 через портал. Конфигурация
// обязана падать на старте, а не оставлять оператора это выяснять.
func TestLoadRejectsRootBasePath(t *testing.T) {
	for _, key := range []string{"JELLYFIN_BASE_PATH", "QBITTORRENT_BASE_PATH"} {
		env := validEnv()
		env[key] = "/"
		if _, err := config.Load(loader(env)); err == nil {
			t.Errorf("%s=/ принят, хотя отключает сервис молча", key)
		}
	}
}
