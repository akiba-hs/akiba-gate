// Package nextcloud логинит резидента в Nextcloud, не зная его пароля.
//
// Как это устроено. Шлюз не умеет ставить cookie сессии на чужом домене и не
// имеет права подделывать вход формой, поэтому он делает единственное, что
// может честно: выдаёт одноразовый код и отправляет с ним браузер в
// приложение-адаптер внутри Nextcloud. Адаптер обменивает код на личность
// (запрос от сервера к серверу, с общим секретом) и логинит человека
// средствами самого Nextcloud.
//
// Пароля во всём этом нет ни на одном шаге, и это главное свойство схемы, а
// не деталь. Шлюз не знает пароля резидента, не хранит его и не передаёт —
// поэтому человек волен задать себе пароль в Nextcloud и менять его когда
// угодно: вход через портал от пароля не зависит вовсе.
//
// Требования к коду и как они выполнены:
//
//   - криптографически случайный — 32 байта из crypto/rand;
//   - короткий срок жизни — codeTTL, одна минута;
//   - одноразовый — обмен удаляет запись под мьютексом, повтор невозможен;
//   - не содержит Telegram-ID — код это просто ключ к записи в памяти;
//   - привязан к flow — к nonce в куке того браузера, который код запросил
//     (см. Issue), и дополнительно к его адресу.
//
// Про привязку отдельно, потому что она защищает от неочевидной атаки. Без
// неё резидент может получить код на СВОЙ аккаунт и заставить чужой браузер
// открыть ссылку с ним — жертва молча окажется в его Nextcloud и сложит туда
// свои файлы. Переход верхнего уровня по ссылке SameSite=Lax не мешает, так
// что помочь может только то, чего у атакующего нет: nonce, который шлюз
// положил в куку жертвы. Адрес браузера для этого не годится — в локальной
// сети за одним NAT он общий у всех.
//
// Хранилище живёт в памяти. Пережить перезапуск оно не должно и не пытается:
// код живёт минуту, и всё, что теряется при рестарте, — это необходимость
// нажать на карточку Nextcloud второй раз.
package nextcloud

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// codeTTL — сколько живёт выданный код.
	//
	// Минута: столько занимает редирект браузера и обратный запрос адаптера.
	// Больше — шире окно для перехваченного кода, меньше — начнёт мешать
	// медленной сети и человеку, который отвлёкся на переключение вкладок.
	codeTTL = time.Minute

	// codeBytes — длина кода до кодирования. 32 байта, то есть 256 бит
	// энтропии: подобрать за минуту невозможно никакими средствами.
	codeBytes = 32

	// maxCodes — потолок хранилища.
	//
	// Код выдаётся авторизованному резиденту, так что залить память может
	// только свой, но «только свой» — не причина оставлять неограниченный
	// рост. При переполнении отказываем в выдаче: молча выбрасывать чужие
	// живые коды означало бы ломать вход тем, кто уже в процессе.
	maxCodes = 4096
)

// Ошибки обмена. Наружу они не различаются намеренно — см. Redeem.
var (
	// ErrUnknownCode — кода нет, он уже использован или просрочен.
	ErrUnknownCode = errors.New("nextcloud: код неизвестен или уже использован")
	// ErrWrongClient — код предъявлен не тем браузером, который его получил.
	ErrWrongClient = errors.New("nextcloud: код предъявлен другим клиентом")
	// ErrTooManyCodes — хранилище переполнено.
	ErrTooManyCodes = errors.New("nextcloud: слишком много незавершённых входов")
)

// Identity — то, ради чего затевается обмен: кого именно логинить.
type Identity struct {
	// UID — имя учётной записи в Nextcloud. Совпадает с auth.Claims.UID().
	UID string
	// DisplayName — человекочитаемое имя для карточки в Nextcloud.
	DisplayName string
	// Username — ник в Telegram. Нужен только журналу.
	Username string
}

// issued — выданный, но ещё не использованный код.
type issued struct {
	identity Identity
	// boundToNonce — код выдан вместе с кукой, и обмен обязан её предъявить.
	// Отдельный флаг, а не «пустой хеш»: нулевой массив — это законный хеш
	// пустой строки, и без флага пустой nonce подошёл бы к такому коду.
	boundToNonce bool
	// nonceHash — SHA-256 от значения куки. Хранится именно хеш: дамп памяти
	// шлюза не должен давать готовый пропуск.
	nonceHash [sha256.Size]byte
	clientIP  string
	expiresAt time.Time
}

// Codes — хранилище одноразовых кодов.
type Codes struct {
	ttl  time.Duration
	now  func() time.Time
	rand func([]byte) (int, error)

	mu    sync.Mutex
	codes map[string]issued
}

// NewCodes создаёт хранилище.
func NewCodes() *Codes {
	return &Codes{
		ttl:   codeTTL,
		now:   time.Now,
		rand:  rand.Read,
		codes: make(map[string]issued),
	}
}

// Issue выдаёт код и, если bindNonce, nonce для куки.
//
// Возвращаются две строки: код (уходит в адрес) и nonce (уходит в куку). Обмен
// потребует обоих, поэтому одного лишь подсмотренного адреса не хватит.
//
// bindNonce=false нужен там, где кука до приложения-адаптера физически не
// доедет: у портала и Nextcloud нет общего родительского домена (Nextcloud
// адресуется по IP). Тогда nonce пуст и не спрашивается — притворяться, что
// привязка работает, было бы хуже, чем честно её не иметь.
//
// clientIP — вторая, более слабая привязка. Пустой означает, что она выключена.
func (c *Codes) Issue(id Identity, clientIP string, bindNonce bool) (code, nonce string, err error) {
	raw := make([]byte, codeBytes)
	if _, err := c.rand(raw); err != nil {
		return "", "", fmt.Errorf("nextcloud: генерация кода: %w", err)
	}
	code = base64.RawURLEncoding.EncodeToString(raw)

	if bindNonce {
		rawNonce := make([]byte, codeBytes)
		if _, err := c.rand(rawNonce); err != nil {
			return "", "", fmt.Errorf("nextcloud: генерация nonce: %w", err)
		}
		nonce = base64.RawURLEncoding.EncodeToString(rawNonce)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Чистим на каждой выдаче, а не по таймеру: выдача — единственное
	// событие, увеличивающее хранилище, и отдельная горутина ради десятка
	// записей была бы дороже самой уборки.
	c.sweepLocked()
	// Прошлый незавершённый код этого же человека выбрасываем: воспользоваться
	// он может только одним, а без этого резидент, дёргающий /nextcloud в
	// цикле, забил бы хранилище и оставил без входа всех остальных.
	for old, rec := range c.codes {
		if rec.identity.UID == id.UID {
			delete(c.codes, old)
		}
	}
	if len(c.codes) >= maxCodes {
		return "", "", ErrTooManyCodes
	}
	c.codes[code] = issued{
		identity:     id,
		boundToNonce: bindNonce,
		nonceHash:    sha256.Sum256([]byte(nonce)),
		clientIP:     clientIP,
		expiresAt:    c.now().Add(c.ttl),
	}
	return code, nonce, nil
}

// Redeem обменивает код на личность и уничтожает его.
//
// Защита от повторного использования здесь и есть: запись удаляется в той же
// критической секции, в которой читается, поэтому два одновременных обмена
// одного кода не могут оба оказаться успешными.
//
// nonce обязателен всегда: это и есть привязка к тому браузеру, который код
// запрашивал. clientIP сверяется дополнительно и только если код выдавался с
// такой привязкой — она отключается для сетей, где шлюз и Nextcloud видят
// клиента под разными адресами.
func (c *Codes) Redeem(code, nonce, clientIP string) (Identity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	rec, ok := c.codes[code]
	if !ok {
		return Identity{}, ErrUnknownCode
	}
	// Удаляем в любом случае, даже при несовпадении адреса: код, которым уже
	// пытались воспользоваться неправильно, доверия не заслуживает, а
	// оставленный жить он дал бы атакующему ещё попытки в пределах минуты.
	delete(c.codes, code)

	if !c.now().Before(rec.expiresAt) {
		return Identity{}, ErrUnknownCode
	}
	if rec.boundToNonce {
		// Сравнение постоянного времени: nonce — секрет, и подбирать его по
		// времени ответа не должно быть возможно.
		got := sha256.Sum256([]byte(nonce))
		if subtle.ConstantTimeCompare(got[:], rec.nonceHash[:]) != 1 {
			return Identity{}, ErrWrongClient
		}
	}
	if rec.clientIP != "" && rec.clientIP != clientIP {
		return Identity{}, ErrWrongClient
	}
	return rec.identity, nil
}

// Len сообщает, сколько кодов сейчас ждут обмена. Нужен тестам.
func (c *Codes) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	return len(c.codes)
}

// sweepLocked выбрасывает просроченные записи. Вызывается под мьютексом.
func (c *Codes) sweepLocked() {
	now := c.now()
	for code, rec := range c.codes {
		if !now.Before(rec.expiresAt) {
			delete(c.codes, code)
		}
	}
}
