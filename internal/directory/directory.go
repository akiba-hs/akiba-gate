// Пакет directory ведёт список резидентов: пополняет его входами и чистит по
// составу группового чата.
//
// Почему список вообще нужен, если резиденты живут в Telegram. Админке надо
// показать, кому что выдано, а выданное хранится у нас. Список в Telegram
// боту целиком недоступен: getChatMember отвечает про одного человека, а
// «дай всех участников» Bot API не умеет для обычных групп. Поэтому список
// собирается тем единственным способом, который доступен честно, — по факту
// входа: человек авторизовался, значит он есть.
//
// Отсюда же и разделение обязанностей. Пополняет список вход (Recorder),
// сокращает — сверка с чатом (Reconciler). Сверка намеренно не добавляет
// никого: спросить у Telegram «кто ещё есть в чате» она не может, и любое
// добавление было бы выдумкой.
package directory

import (
	"context"
	"log/slog"
	"sync"

	"github.com/akiba-hs/akiba-gate/internal/audit"
	"github.com/akiba-hs/akiba-gate/internal/auth"
)

// Store — то, что умеет хранить резидентов.
type Store interface {
	UpsertResident(ctx context.Context, r audit.Resident) error
	Residents(ctx context.Context) ([]audit.Resident, error)
	DeleteResident(ctx context.Context, telegramID string) error
}

// Recorder заводит резидента при входе и обновляет его данные.
//
// Пишет в базу не на каждый запрос, а только когда что-то изменилось:
// портал и прокси дёргаются десятки раз в минуту, а соединение к SQLite одно.
// Признак изменения — сами данные человека, поэтому смена ника или фамилии
// доезжает до базы на первом же запросе после входа, без ожидания рестарта.
type Recorder struct {
	Store Store
	Log   *slog.Logger

	mu   sync.Mutex
	last map[string]string // telegramID -> отпечаток последних записанных данных
}

// NewRecorder создаёт регистратор.
func NewRecorder(store Store, log *slog.Logger) *Recorder {
	return &Recorder{Store: store, Log: log, last: make(map[string]string)}
}

// Note записывает человека, если о нём ещё не знали или он изменился.
//
// Ошибка записи только логируется: не пустить резидента в систему из-за того,
// что не удалось обновить его фамилию, — плохой размен.
func (rec *Recorder) Note(ctx context.Context, c *auth.Claims) {
	if rec == nil || c == nil || c.TelegramID == "" {
		return
	}
	// Не резидентов не записываем: список — это список резидентов, и
	// посторонний, заглянувший на портал, в нём не нужен.
	if !c.IsResident {
		return
	}
	fingerprint := c.Username + "\x00" + c.FirstName + "\x00" + c.LastName

	rec.mu.Lock()
	unchanged := rec.last[c.TelegramID] == fingerprint
	rec.mu.Unlock()
	if unchanged {
		return
	}

	resident := audit.Resident{
		TelegramID: c.TelegramID,
		Username:   c.Username,
		FirstName:  c.FirstName,
		LastName:   c.LastName,
	}
	if err := rec.Store.UpsertResident(ctx, resident); err != nil {
		rec.Log.Error("не удалось записать резидента", "error", err, "user", c.UID())
		return
	}

	rec.mu.Lock()
	_, seen := rec.last[c.TelegramID]
	rec.last[c.TelegramID] = fingerprint
	rec.mu.Unlock()

	if seen {
		rec.Log.Info("данные резидента обновлены",
			"user", c.UID(), "username", c.Username)
		return
	}
	rec.Log.Info("резидент добавлен в список",
		"user", c.UID(), "username", c.Username, "display_name", c.DisplayName())
}

// Forget убирает человека из памяти регистратора.
//
// Нужен после удаления из базы: без этого отпечаток остался бы в памяти, и
// вернувшийся в чат человек не был бы записан заново — до перезапуска шлюза
// он оставался бы невидимым для админки.
func (rec *Recorder) Forget(telegramID string) {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	delete(rec.last, telegramID)
	rec.mu.Unlock()
}
