// Пакет testsupport содержит помощники для тестов: генерацию ключей,
// выпуск токенов и сборку .torrent-файлов.
//
// Вынесен в обычный (не _test) пакет, потому что нужен сразу нескольким
// тестируемым пакетам, а дублировать генерацию RSA-ключа в каждом — лишнее.
package testsupport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/i18n"
	"github.com/golang-jwt/jwt/v5"
)

// KeyPair — пара ключей для выпуска и проверки тестовых токенов.
type KeyPair struct {
	Private   *rsa.PrivateKey
	PublicPEM []byte
}

// NewKeyPair генерирует ключ. 2048 бит: быстрее, чем 4096, и это ровно то,
// чем пользуется auth-service.
func NewKeyPair(t *testing.T) KeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("сериализация публичного ключа: %v", err)
	}
	return KeyPair{
		Private:   key,
		PublicPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	}
}

// TokenOptions описывает содержимое тестового токена.
type TokenOptions struct {
	TelegramID string
	Username   string
	FirstName  string
	LastName   string
	PhotoURL   string
	IsResident bool
	ExpiresIn  time.Duration
}

// Token выпускает токен в том же формате, что и auth-service.
func (kp KeyPair) Token(t *testing.T, o TokenOptions) string {
	t.Helper()
	if o.TelegramID == "" {
		o.TelegramID = "42424242"
	}
	if o.ExpiresIn == 0 {
		o.ExpiresIn = time.Hour
	}
	claims := jwt.MapClaims{
		"id":          o.TelegramID,
		"username":    o.Username,
		"first_name":  o.FirstName,
		"last_name":   o.LastName,
		"photo_url":   o.PhotoURL,
		"auth_date":   fmt.Sprint(time.Now().Unix()),
		"is_resident": o.IsResident,
		"exp":         time.Now().Add(o.ExpiresIn).Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(kp.Private)
	if err != nil {
		t.Fatalf("подпись токена: %v", err)
	}
	return signed
}

// ResidentToken — короткая форма для «валидный резидент».
func (kp KeyPair) ResidentToken(t *testing.T) string {
	t.Helper()
	return kp.Token(t, TokenOptions{
		TelegramID: "42424242", Username: "alice",
		FirstName: "Alice", LastName: "Example", IsResident: true,
	})
}

// TorrentFile собирает минимальный корректный .torrent с заданным именем.
//
// Строим байты вручную: infohash — это SHA-1 от точных байтов словаря info,
// поэтому тест обязан оперировать сырым bencode, а не структурами.
func TorrentFile(name string, pieceLength int, piecesHash string) []byte {
	const announce = "http://tracker.example/announce"
	info := InfoDictOf(name, pieceLength, piecesHash)
	return []byte(fmt.Sprintf("d8:announce%d:%s4:info%se", len(announce), announce, info))
}

// InfoDictOf возвращает байты словаря info из файла, собранного TorrentFile.
// Нужен, чтобы тест мог посчитать ожидаемый infohash независимо от кода.
func InfoDictOf(name string, pieceLength int, piecesHash string) []byte {
	// Ключи идут в порядке, требуемом спецификацией (лексикографически),
	// а длины строк считаются в байтах — иначе имя с кириллицей всё сломает.
	return []byte(fmt.Sprintf("d6:lengthi1024e4:name%d:%s12:piece lengthi%de6:pieces%d:%se",
		len(name), name, pieceLength, len(piecesHash), piecesHash))
}

// Messages возвращает заполненный набор текстов для тестов.
//
// Значения намеренно узнаваемые: если такая строка всплывёт в неожиданном
// месте страницы, это сразу видно.
func Messages() i18n.Messages {
	return i18n.Messages{
		PortalTitle:        "Сервисы резидентов Akiba",
		PortalSubtitle:     "Войдите через Telegram",
		LoginButton:        "Войти через Telegram",
		LogoutButton:       "Выйти",
		ResidentBadge:      "резидент",
		NotResidentBadge:   "не резидент",
		NoServices:         "УРА!!! Ты резидент!",
		NotResidentError:   "Вы вошли, но не состоите в чате резидентов — сервисы недоступны.",
		WrongHostTitle:     "Портал открыт по чужому адресу.",
		WrongHostText:      "Правильный адрес:",
		ReturnsElsewhere:   "эта страница дождётся входа сама и обновится",
		ServiceJellyfin:    "Jellyfin",
		ServiceJellyfinSub: "Медиатека резидентов",
		ServiceQbit:        "qBittorrent",
		ServiceQbitSub:     "Загрузки",
		ServiceNextcloud:   "Nextcloud",
		ServiceNextcloudSb: "Файлы",
		TorrentAdded:       "Резидент {user} добавил {torrent}",
		TorrentDownloaded:  "Торрент {torrent} загрузился",
		ServiceAdmin:       "Управление резидентами",
		ServiceAdminSub:    "Кому какие сервисы доступны",

		AdminTitle:           "Управление резидентами",
		AdminSubtitle:        "Нажмите на резидента, чтобы изменить доступ.",
		AdminBackToPortal:    "К сервисам",
		AdminEmpty:           "Пока никто не заходил.",
		AdminNoServices:      "нет доступа",
		AdminNoUsername:      "без ника",
		AdminRootBadge:       "администратор из конфигурации",
		AdminRootLocked:      "Права администратора из конфигурации менять нельзя.",
		AdminUnknownResident: "Такого резидента нет в списке.",
		AdminLoadError:       "Не удалось прочитать список резидентов.",
		AdminSaved:           "Доступы сохранены.",
		AdminSaveButton:      "Сохранить",
		AdminCancelButton:    "Отмена",
	}
}

// StaticTexts — неизменные тексты для тестов, подходящие под portal.Texts.
type StaticTexts struct{ M i18n.Messages }

func (t StaticTexts) Messages() i18n.Messages {
	if t.M.PortalTitle == "" {
		return Messages()
	}
	return t.M
}

// WriteMessages кладёт набор текстов во временный файл и возвращает путь.
func WriteMessages(t *testing.T, m i18n.Messages) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "i18n.json")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("сборка файла переводов: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("запись файла переводов: %v", err)
	}
	return path
}
