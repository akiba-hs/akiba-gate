// Package access решает, какие сервисы доступны конкретному человеку.
//
// Зачем отдельный пакет. Право доступа спрашивают в двух разных местах: портал
// решает, показывать ли карточку, а маршрут — пускать ли по адресу. Разложи
// это решение по обоим местам, и они разойдутся: карточка исчезнет, а адрес
// останется рабочим — или наоборот.
//
// Поэтому решение вынесено за интерфейс Policy и принимается ровно в одном
// месте. Портал спрашивает у него список карточек, маршруты — право на
// конкретный сервис. Появится персональный доступ — меняется только
// реализация Policy, всё остальное остаётся как есть.
package access

import (
	"context"
	"net/http"
	"slices"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/i18n"
)

// ID — идентификатор сервиса. Строка, а не число: она попадёт в конфигурацию
// и в базу, когда доступ станет персональным, и должна читаться человеком.
type ID string

const (
	Jellyfin    ID = "jellyfin"
	QBittorrent ID = "qbittorrent"
	Nextcloud   ID = "nextcloud"
	// Admin — управление резидентами. Всегда последний в списке: это не
	// сервис для жизни, а инструмент, и он не должен спорить за внимание с
	// медиатекой и загрузками.
	Admin ID = "admin"
)

// All перечисляет все известные сервисы в порядке показа на портале.
// Admin намеренно замыкает список — см. комментарий к константе.
func All() []ID { return []ID{Jellyfin, QBittorrent, Nextcloud, Admin} }

// Known сообщает, что идентификатор — действительно наш сервис.
//
// Нужен на входе из внешнего мира: форма админки присылает список галочек, и
// без проверки в базу уехала бы любая строка, которую туда впишут.
func Known(id ID) bool { return slices.Contains(All(), id) }

// Service — карточка сервиса, готовая к показу.
type Service struct {
	ID          ID
	Title       string
	Description string
	URL         string
}

// Catalog знает адреса и названия сервисов. Тексты берутся из i18n на каждый
// вызов: они должны меняться правкой файла, без перезапуска.
type Catalog struct {
	JellyfinURL  string
	QbitURL      string
	NextcloudURL string
	AdminURL     string
}

// Describe собирает карточку по идентификатору.
func (c Catalog) Describe(id ID, m i18n.Messages) (Service, bool) {
	switch id {
	case Jellyfin:
		return Service{id, m.ServiceJellyfin, m.ServiceJellyfinSub, c.JellyfinURL}, true
	case QBittorrent:
		return Service{id, m.ServiceQbit, m.ServiceQbitSub, c.QbitURL}, true
	case Nextcloud:
		return Service{id, m.ServiceNextcloud, m.ServiceNextcloudSb, c.NextcloudURL}, true
	case Admin:
		return Service{id, m.ServiceAdmin, m.ServiceAdminSub, c.AdminURL}, true
	}
	return Service{}, false
}

// Policy решает, к каким сервисам допущен резидент.
//
// Возвращается именно список, а не «да/нет» на каждый сервис: порталу нужен
// весь набор сразу, и два разных способа спросить одно и то же неминуемо
// разъехались бы.
type Policy interface {
	// AllowedFor возвращает идентификаторы доступных сервисов.
	// Для nil-claims (аноним) обязан вернуть пустой список.
	//
	// Ошибка в сигнатуре есть с самого начала, хотя сегодняшняя реализация
	// её никогда не возвращает. Персональные списки будут жить в базе, и без
	// ошибки такая реализация была бы вынуждена выбирать между тихим
	// открытием доступа при сбое запроса и тихой блокировкой всех — оба
	// варианта нельзя даже заметить в журнале. Добавить её потом означало бы
	// править все места разом; сейчас их два.
	AllowedFor(ctx context.Context, c *auth.Claims) ([]ID, error)
}

// ResidentPolicy — правило «резиденту доступно всё».
//
// Нужна там, где персональные списки не участвуют: в тестах соседних пакетов,
// которым важен не состав прав, а поведение вокруг них.
type ResidentPolicy struct {
	// Services — что именно считается «всем».
	Services []ID
}

func (p ResidentPolicy) AllowedFor(_ context.Context, c *auth.Claims) ([]ID, error) {
	if c == nil || !c.IsResident {
		return nil, nil
	}
	return slices.Clone(p.Services), nil
}

// Grants отдаёт выданные человеку права. Интерфейс, а не *audit.Store, чтобы
// политика тестировалась без базы.
type Grants interface {
	ResidentServices(ctx context.Context, telegramID string) ([]string, error)
}

// StorePolicy — персональный доступ: у каждого ровно то, что выдал
// администратор, и ничего сверх.
//
// Умолчание — «ничего». Новый резидент входит и видит пустой портал, пока
// его не откроют в админке. Обратное умолчание («всё, пока не отняли»)
// означало бы, что любой попавший в чат человек получает доступ ко всему на
// то время, пока администратор не заметит его появления.
type StorePolicy struct {
	Grants Grants
	// RootAdmin — Telegram-ID администратора из конфигурации. Ему доступно
	// всё и всегда, мимо базы: снять с него права нельзя ничем, кроме правки
	// конфигурации, иначе второй администратор мог бы запереть первого
	// снаружи собственной системы.
	RootAdmin string
}

// IsRoot сообщает, что это тот самый администратор из конфигурации.
func (p StorePolicy) IsRoot(telegramID string) bool {
	return p.RootAdmin != "" && telegramID == p.RootAdmin
}

func (p StorePolicy) AllowedFor(ctx context.Context, c *auth.Claims) ([]ID, error) {
	if c == nil {
		return nil, nil
	}
	// Признак резидента проверяется раньше базы: человек, выбывший из чата,
	// не должен пользоваться правами, выданными когда-то.
	if p.IsRoot(c.TelegramID) {
		return All(), nil
	}
	if !c.IsResident {
		return nil, nil
	}
	granted, err := p.Grants.ResidentServices(ctx, c.TelegramID)
	if err != nil {
		return nil, err
	}
	// Фильтруем по известным: в базе может остаться право на сервис, который
	// с тех пор убрали из кода, и отдавать его наружу незачем.
	out := make([]ID, 0, len(granted))
	for _, raw := range granted {
		if id := ID(raw); Known(id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// ServicesFor собирает карточки доступных сервисов в порядке All().
func ServicesFor(ctx context.Context, p Policy, cat Catalog, m i18n.Messages, c *auth.Claims) ([]Service, error) {
	allowed, err := p.AllowedFor(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(allowed) == 0 {
		return nil, nil
	}
	out := make([]Service, 0, len(allowed))
	for _, id := range All() {
		if !slices.Contains(allowed, id) {
			continue
		}
		if svc, ok := cat.Describe(id, m); ok {
			out = append(out, svc)
		}
	}
	return out, nil
}

// Require пропускает запрос только к разрешённому сервису.
//
// Скрыть карточку недостаточно: адрес сервиса легко набрать руками, и без
// этой проверки персональный доступ был бы косметикой.
func Require(p Policy, id ID, log Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := auth.FromContext(r.Context())
		allowed, err := p.AllowedFor(r.Context(), claims)
		if err != nil {
			// Не смогли выяснить права — закрываем. Открыть «на всякий
			// случай» значило бы превратить сбой базы в дыру.
			log.Warn("не удалось выяснить права доступа, запрос отклонён",
				"user", uidOf(claims), "service", string(id), "error", err)
			http.Error(w, "не удалось проверить доступ", http.StatusServiceUnavailable)
			return
		}
		if !slices.Contains(allowed, id) {
			log.Warn("доступ к сервису запрещён политикой",
				"user", uidOf(claims), "service", string(id))
			http.Error(w, "доступ к сервису закрыт", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Logger — то немногое от журнала, что нужно этому пакету.
type Logger interface {
	Warn(msg string, args ...any)
}

func uidOf(c *auth.Claims) string {
	if c == nil {
		return "аноним"
	}
	return c.UID()
}
