package directory

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/audit"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
)

// Chat отвечает, состоит ли человек в групповом чате, и отдаёт его профиль.
// Интерфейс, а не *tgnotify.Notifier, чтобы сверка тестировалась без сети.
type Chat interface {
	ChatMember(ctx context.Context, telegramID string) (tgnotify.Membership, tgnotify.ChatMemberProfile, error)
}

const (
	// reconcileInterval — как часто сверка вообще выполняется.
	//
	// Запускается она открытием админки, а открывают её сколько угодно раз
	// подряд. Без паузы каждое обновление страницы означало бы запрос в
	// Telegram на каждого резидента — быстрый способ упереться в лимиты Bot
	// API и получить временный бан на отправку сообщений.
	reconcileInterval = 5 * time.Minute

	// reconcileTimeout ограничивает всю сверку целиком.
	reconcileTimeout = 2 * time.Minute

	// maxDeletesPerRun и maxDeleteShare — предохранитель от массового удаления.
	//
	// Удаление необратимо: вместе с человеком каскадом исчезают выданные ему
	// права, и восстановить их можно только руками. При этом Telegram умеет
	// отвечать уверенно и неверно: неправильный TELEGRAM_CHAT_ID даёт
	// «user not found» на каждого, то есть MembershipOut для всех — и одно
	// открытие админки вычистило бы весь список.
	//
	// Поэтому пачку сверх порога не применяем вовсе: лучше оставить в списке
	// нескольких выбывших до разбирательства, чем стереть всех разом.
	maxDeletesPerRun = 3
	maxDeleteShare   = 0.3

	// betweenRequests — пауза между запросами к Telegram.
	//
	// Bot API держит около 30 запросов в секунду, и резидентов у нас
	// десятки, так что упереться сложно. Пауза стоит на случай, когда
	// список однажды вырастет: лучше сверять чуть дольше, чем словить 429.
	betweenRequests = 100 * time.Millisecond
)

// Reconciler сверяет список резидентов с составом группового чата.
//
// Что он делает и чего не делает. Убирает тех, кого в чате больше нет, и
// обновляет имена оставшихся. Никого не добавляет: Bot API не умеет отдавать
// список участников обычной группы, поэтому «кто ещё есть в чате» ему просто
// неоткуда узнать, и любое добавление было бы выдумкой. Новые появляются
// сами — первым же входом (см. Recorder).
//
// Работает в отдельной горутине, запущенной открытием админки, и на саму
// админку не влияет: страница рисуется по тому, что уже лежит в базе. Об
// удалении человека станет известно при следующем её открытии — задержка
// осознанная, ради того чтобы страница открывалась мгновенно.
type Reconciler struct {
	Store    Store
	Chat     Chat
	Recorder *Recorder
	// Protected — Telegram-ID, которые нельзя удалять ни при каких ответах
	// Telegram. Здесь живёт администратор из конфигурации: сбой проверки не
	// должен уносить единственного человека, способного раздавать доступ.
	Protected map[string]bool
	Log       *slog.Logger

	now func() time.Time

	mu      sync.Mutex
	running bool
	lastRun time.Time
	// wg считает запущенные сверки: шлюз обязан дождаться их перед закрытием
	// базы, иначе удаление выбывших обрывается на середине с «database is
	// closed».
	wg sync.WaitGroup
}

// Wait дожидается завершения запущенных сверок.
func (r *Reconciler) Wait() {
	if r == nil {
		return
	}
	r.wg.Wait()
}

// NewReconciler создаёт сверку.
func NewReconciler(store Store, chat Chat, rec *Recorder, protected []string, log *slog.Logger) *Reconciler {
	set := make(map[string]bool, len(protected))
	for _, id := range protected {
		if id != "" {
			set[id] = true
		}
	}
	return &Reconciler{
		Store: store, Chat: chat, Recorder: rec,
		Protected: set, Log: log, now: time.Now,
	}
}

// Trigger запускает сверку в фоне, если она не идёт и пауза истекла.
//
// Возвращает признак запуска — он нужен только тестам и журналу: вызывающий
// (админка) в любом случае продолжает рисовать страницу.
func (r *Reconciler) Trigger(ctx context.Context) bool {
	if r == nil || r.Chat == nil {
		return false
	}
	r.mu.Lock()
	now := r.now()
	if r.running || (!r.lastRun.IsZero() && now.Sub(r.lastRun) < reconcileInterval) {
		r.mu.Unlock()
		return false
	}
	r.running = true
	r.lastRun = now
	r.mu.Unlock()

	// Контекст запроса не годится: страница админки отдаётся раньше, чем
	// сверка закончится, и с ним она обрывалась бы на первом же резиденте.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			r.mu.Lock()
			r.running = false
			r.mu.Unlock()
		}()
		runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reconcileTimeout)
		defer cancel()
		r.Run(runCtx)
	}()
	return true
}

// Run выполняет сверку синхронно. Публичный ради тестов и ручного вызова.
func (r *Reconciler) Run(ctx context.Context) {
	residents, err := r.Store.Residents(ctx)
	if err != nil {
		r.Log.Error("не удалось прочитать список резидентов для сверки", "error", err)
		return
	}

	// Сначала опрашиваем всех и только потом применяем удаления: решение
	// «не удалять ничего» принимается по всей пачке сразу, а не по первым
	// нескольким, до которых успели дойти.
	var (
		toDelete []audit.Resident
		updated  int
	)
	for i, resident := range residents {
		if ctx.Err() != nil {
			r.Log.Warn("сверка состава чата прервана",
				"checked", i, "total", len(residents))
			return
		}
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(betweenRequests):
			}
		}

		status, profile, err := r.Chat.ChatMember(ctx, resident.TelegramID)
		if err != nil {
			// Сбой связи — не повод объявлять человека выбывшим. Пропускаем:
			// следующая сверка разберётся.
			r.Log.Warn("не удалось проверить участие резидента в чате",
				"error", err, "user", "tg"+resident.TelegramID)
			continue
		}

		switch status {
		case tgnotify.MembershipUnknown:
			// Состав чата выяснить не удалось. Молча пропускаем: удалять по
			// незнанию нельзя, а обновлять — нечем.
			continue

		case tgnotify.MembershipOut:
			if r.Protected[resident.TelegramID] {
				r.Log.Warn("резидент отсутствует в чате, но защищён конфигурацией — оставлен",
					"user", "tg"+resident.TelegramID)
				continue
			}
			toDelete = append(toDelete, resident)

		case tgnotify.MembershipIn:
			if !profileChanged(resident, profile) {
				continue
			}
			fresh := audit.Resident{
				TelegramID: resident.TelegramID,
				Username:   profile.Username,
				FirstName:  profile.FirstName,
				LastName:   profile.LastName,
			}
			if err := r.Store.UpsertResident(ctx, fresh); err != nil {
				r.Log.Error("не удалось обновить данные резидента",
					"error", err, "user", "tg"+resident.TelegramID)
				continue
			}
			// Отпечаток в регистраторе устарел: без сброса он не дал бы
			// записать данные, если человек вернёт прежнее имя.
			r.Recorder.Forget(resident.TelegramID)
			updated++
			r.Log.Info("данные резидента обновлены по данным чата",
				"user", "tg"+resident.TelegramID, "username", profile.Username)
		}
	}

	removed := r.applyDeletions(ctx, toDelete, len(residents))
	if removed > 0 || updated > 0 {
		r.Log.Info("сверка состава чата завершена",
			"checked", len(residents), "removed", removed, "updated", updated)
	}
}

// applyDeletions удаляет выбывших, если их не подозрительно много.
//
// Порог здесь — не оптимизация, а защита от уверенно неверного ответа
// Telegram (см. maxDeletesPerRun). Отказ применить пачку всегда громкий: это
// ровно тот случай, когда нужно посмотреть глазами.
func (r *Reconciler) applyDeletions(ctx context.Context, out []audit.Resident, total int) int {
	if len(out) == 0 {
		return 0
	}
	tooMany := len(out) > maxDeletesPerRun &&
		float64(len(out)) > float64(total)*maxDeleteShare
	if tooMany {
		r.Log.Error("сверка состава чата хотела удалить подозрительно многих — "+
			"не удалено никого; проверьте TELEGRAM_CHAT_ID и права бота в чате",
			"would_remove", len(out), "total", total)
		return 0
	}

	var removed int
	for _, resident := range out {
		if err := r.Store.DeleteResident(ctx, resident.TelegramID); err != nil {
			r.Log.Error("не удалось удалить выбывшего резидента",
				"error", err, "user", "tg"+resident.TelegramID)
			continue
		}
		r.Recorder.Forget(resident.TelegramID)
		removed++
		r.Log.Info("резидент удалён: его больше нет в групповом чате",
			"user", "tg"+resident.TelegramID, "username", resident.Username)
	}
	return removed
}

// profileChanged сравнивает то, что лежит в базе, с ответом Telegram.
//
// Пустой профиль игнорируется: Telegram отдаёт его не всегда, и затирать им
// известное имя значило бы терять данные на ровном месте.
func profileChanged(stored audit.Resident, fresh tgnotify.ChatMemberProfile) bool {
	if fresh.FirstName == "" && fresh.LastName == "" && fresh.Username == "" {
		return false
	}
	return stored.Username != fresh.Username ||
		stored.FirstName != fresh.FirstName ||
		stored.LastName != fresh.LastName
}
