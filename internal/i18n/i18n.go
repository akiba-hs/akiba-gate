// Пакет i18n держит тексты интерфейса в отдельном JSON-файле и позволяет
// править их без пересборки и перезапуска.
//
// Файл читается не на каждый запрос: разобранные строки лежат в памяти, и
// проверка «не изменился ли файл» делается не чаще, чем раз в TTL. Это важно
// для страниц, которые открывают десятки раз в минуту, и для сообщений бота,
// которые обязаны быть свежими.
//
// Отдельно — поведение при испорченном файле. Тексты нужны всегда, поэтому
// сломанный или неполный JSON никогда не доходит до резидента: отдаются
// прежние строки из памяти, а сам файл переписывается ими же. Так оператор,
// сломавший файл, видит его починенным, а не пустой интерфейс.
package i18n

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Messages — полный набор текстов. Поля обязательные все до единого:
// пустая строка в интерфейсе выглядит как поломка вёрстки, и лучше
// отвергнуть такой файл целиком, чем показать дырку.
type Messages struct {
	PortalTitle        string `json:"portal_title"`
	PortalSubtitle     string `json:"portal_subtitle"`
	LoginButton        string `json:"login_button"`
	LogoutButton       string `json:"logout_button"`
	ResidentBadge      string `json:"resident_badge"`
	NotResidentBadge   string `json:"not_resident_badge"`
	NoServices         string `json:"no_services"`
	NotResidentError   string `json:"not_resident_error"`
	WrongHostTitle     string `json:"wrong_host_title"`
	WrongHostText      string `json:"wrong_host_text"`
	ReturnsElsewhere   string `json:"returns_elsewhere"`
	ServiceJellyfin    string `json:"service_jellyfin"`
	ServiceJellyfinSub string `json:"service_jellyfin_sub"`
	ServiceQbit        string `json:"service_qbittorrent"`
	ServiceQbitSub     string `json:"service_qbittorrent_sub"`
	ServiceNextcloud   string `json:"service_nextcloud"`
	ServiceNextcloudSb string `json:"service_nextcloud_sub"`
	ServiceAdmin       string `json:"service_admin"`
	ServiceAdminSub    string `json:"service_admin_sub"`

	// Тексты админки.
	AdminTitle           string `json:"admin_title"`
	AdminSubtitle        string `json:"admin_subtitle"`
	AdminBackToPortal    string `json:"admin_back_to_portal"`
	AdminEmpty           string `json:"admin_empty"`
	AdminNoServices      string `json:"admin_no_services"`
	AdminNoUsername      string `json:"admin_no_username"`
	AdminRootBadge       string `json:"admin_root_badge"`
	AdminRootLocked      string `json:"admin_root_locked"`
	AdminUnknownResident string `json:"admin_unknown_resident"`
	AdminLoadError       string `json:"admin_load_error"`
	AdminSaved           string `json:"admin_saved"`
	AdminSaveButton      string `json:"admin_save_button"`
	AdminCancelButton    string `json:"admin_cancel_button"`
	// TorrentAdded — шаблон сообщения бота в групповой чат. Плейсхолдеры
	// {user} и {torrent} подставляются как есть, поэтому в файле они обязаны
	// присутствовать.
	TorrentAdded string `json:"torrent_added"`
	// TorrentDownloaded — шаблон личного сообщения о законченной загрузке.
	// Плейсхолдер один — {torrent}: адресат и так знает, что добавлял он.
	TorrentDownloaded string `json:"torrent_downloaded"`
}

// requiredFields перечисляет поля для проверки на пустоту. Держим списком, а
// не рефлексией: так добавление поля заставляет осознанно решить, обязательно
// ли оно, вместо того чтобы молча стать обязательным.
func (m Messages) requiredFields() map[string]string {
	return map[string]string{
		"portal_title":            m.PortalTitle,
		"portal_subtitle":         m.PortalSubtitle,
		"login_button":            m.LoginButton,
		"logout_button":           m.LogoutButton,
		"resident_badge":          m.ResidentBadge,
		"not_resident_badge":      m.NotResidentBadge,
		"no_services":             m.NoServices,
		"not_resident_error":      m.NotResidentError,
		"wrong_host_title":        m.WrongHostTitle,
		"wrong_host_text":         m.WrongHostText,
		"returns_elsewhere":       m.ReturnsElsewhere,
		"service_jellyfin":        m.ServiceJellyfin,
		"service_jellyfin_sub":    m.ServiceJellyfinSub,
		"service_qbittorrent":     m.ServiceQbit,
		"service_qbittorrent_sub": m.ServiceQbitSub,
		"service_nextcloud":       m.ServiceNextcloud,
		"service_nextcloud_sub":   m.ServiceNextcloudSb,
		"service_admin":           m.ServiceAdmin,
		"service_admin_sub":       m.ServiceAdminSub,
		"admin_title":             m.AdminTitle,
		"admin_subtitle":          m.AdminSubtitle,
		"admin_back_to_portal":    m.AdminBackToPortal,
		"admin_empty":             m.AdminEmpty,
		"admin_no_services":       m.AdminNoServices,
		"admin_no_username":       m.AdminNoUsername,
		"admin_root_badge":        m.AdminRootBadge,
		"admin_root_locked":       m.AdminRootLocked,
		"admin_unknown_resident":  m.AdminUnknownResident,
		"admin_load_error":        m.AdminLoadError,
		"admin_saved":             m.AdminSaved,
		"admin_save_button":       m.AdminSaveButton,
		"admin_cancel_button":     m.AdminCancelButton,
		"torrent_added":           m.TorrentAdded,
		"torrent_downloaded":      m.TorrentDownloaded,
	}
}

// Validate проверяет, что файл заполнен целиком.
func (m Messages) Validate() error {
	for name, value := range m.requiredFields() {
		if value == "" {
			return fmt.Errorf("i18n: не заполнено поле %q", name)
		}
	}
	return nil
}

// Bundle отдаёт тексты, перечитывая файл не чаще одного раза в TTL.
type Bundle struct {
	path string
	ttl  time.Duration
	log  *slog.Logger
	now  func() time.Time

	mu sync.Mutex
	// messages — последние заведомо корректные тексты. Пустыми не бывают:
	// первая загрузка происходит при создании и обязана удаться.
	messages Messages
	// checkedAt — когда в последний раз смотрели на файл. Не «когда читали»:
	// после проверки без изменений время тоже обновляется, иначе каждый
	// запрос после истечения TTL снова дёргал бы диск.
	checkedAt time.Time
	// modTime — отметка времени файла, соответствующая messages.
	modTime time.Time
}

// Load читает файл и создаёт набор текстов.
//
// На старте требования жёсткие: без корректного файла сервис не поднимается.
// Мягкое поведение при поломке имеет смысл только тогда, когда есть на что
// откатиться, а при запуске откатываться не на что.
func Load(path string, ttl time.Duration, log *slog.Logger) (*Bundle, error) {
	b := &Bundle{path: path, ttl: ttl, log: log, now: time.Now}
	msgs, mod, err := b.readFile()
	if err != nil {
		return nil, err
	}
	b.messages, b.modTime, b.checkedAt = msgs, mod, b.now()
	return b, nil
}

// SetClock подменяет источник времени. Нужен тестам: ждать реальный TTL
// в тестах недопустимо.
func (b *Bundle) SetClock(now func() time.Time) {
	b.mu.Lock()
	b.now = now
	b.mu.Unlock()
}

// Messages возвращает актуальные тексты, при необходимости перечитав файл.
func (b *Bundle) Messages() Messages {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if now.Sub(b.checkedAt) < b.ttl {
		return b.messages
	}
	// Время проверки обновляем при любом исходе: иначе каждый следующий
	// запрос снова шёл бы на диск.
	b.checkedAt = now

	info, err := os.Stat(b.path)
	if err != nil {
		// Пропавший файл восстанавливаем так же, как испорченный: иначе
		// сервис продолжает работать на текстах из памяти, а следующий
		// перезапуск падает — Load без файла не поднимется.
		if os.IsNotExist(err) {
			b.log.Error("файл переводов пропал, восстанавливаю его из памяти",
				"path", b.path)
			b.restore()
			return b.messages
		}
		b.log.Warn("не удалось проверить файл переводов, остаёмся на прежних текстах",
			"path", b.path, "error", err)
		return b.messages
	}
	if info.ModTime().Equal(b.modTime) {
		return b.messages
	}

	msgs, mod, err := b.readFile()
	if err != nil {
		b.log.Error("файл переводов испорчен, восстанавливаю его из памяти",
			"path", b.path, "error", err)
		b.restore()
		return b.messages
	}
	b.messages, b.modTime = msgs, mod
	b.log.Info("файл переводов перечитан", "path", b.path)
	return b.messages
}

// readFile читает и проверяет файл целиком.
func (b *Bundle) readFile() (Messages, time.Time, error) {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return Messages{}, time.Time{}, fmt.Errorf("i18n: чтение %s: %w", b.path, err)
	}
	info, err := os.Stat(b.path)
	if err != nil {
		return Messages{}, time.Time{}, fmt.Errorf("i18n: %s: %w", b.path, err)
	}
	var msgs Messages
	dec := json.NewDecoder(bytes.NewReader(data))
	// Лишнее поле — почти всегда опечатка в имени нужного, и молча её
	// проглотить значит оставить в интерфейсе пустую строку.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&msgs); err != nil {
		return Messages{}, time.Time{}, fmt.Errorf("i18n: разбор %s: %w", b.path, err)
	}
	if err := msgs.Validate(); err != nil {
		return Messages{}, time.Time{}, err
	}
	return msgs, info.ModTime(), nil
}

// restore переписывает файл текстами из памяти.
//
// Отметку времени после записи запоминаем обязательно: сама запись изменяет
// mtime, и без этого следующая проверка увидела бы «файл изменился» и снова
// пошла бы читать то, что мы только что записали сами.
func (b *Bundle) restore() {
	data, err := json.MarshalIndent(b.messages, "", "  ")
	if err != nil {
		b.log.Error("не удалось собрать файл переводов для восстановления", "error", err)
		return
	}
	data = append(data, '\n')
	if err := os.WriteFile(b.path, data, 0o644); err != nil {
		b.log.Error("не удалось восстановить файл переводов",
			"path", b.path, "error", err)
		return
	}
	if info, err := os.Stat(b.path); err == nil {
		b.modTime = info.ModTime()
	}
	b.log.Info("файл переводов восстановлен из памяти", "path", b.path)
}
