package jellyfin

import (
	"sync"
	"time"
)

// Ограничитель попыток подтверждения кода быстрого подключения.
//
// Код быстрого подключения — шесть цифр, то есть миллион вариантов, и он
// действует, пока человек не подтвердит его или пока не истечёт. Без
// ограничения резидент может перебирать эти шесть цифр скриптом: каждое
// попадание подтверждает чужой ожидающий вход, привязывая чужое устройство к
// сессии, которую запросил не его владелец. Заодно каждая попытка — это
// настоящий запрос к Jellyfin от общей служебной учётки, так что перебор
// нагружает и сам медиасервер.
//
// Ограничение персональное: общий счётчик позволил бы одному резиденту
// закрыть вход всем остальным.
const (
	// maxAttempts — сколько подтверждений разрешено в окне.
	//
	// Десять: человек ошибается в шести цифрах один-два раза, а перебор при
	// таком темпе занял бы годы.
	maxAttempts = 10

	// attemptWindow — длина окна.
	attemptWindow = time.Minute

	// maxAttemptEntries — потолок таблицы счётчиков.
	//
	// Ключ — Telegram-ID резидента, то есть строк здесь столько же, сколько
	// людей в чате. Потолок нужен не от них, а от того, что таблица живёт всё
	// время работы шлюза: при переполнении она чистится целиком, и это
	// правильнее, чем расти без предела.
	maxAttemptEntries = 4096
)

// AttemptLimiter считает попытки подтверждения кода по резидентам.
//
// Один экземпляр делится между формой и её JSON-двойником: иначе резиденту
// доставалось бы по отдельной норме на каждый путь, и ограничение обходилось
// бы чередованием.
type AttemptLimiter struct {
	now func() time.Time

	mu      sync.Mutex
	windows map[string]attemptWindowState
}

type attemptWindowState struct {
	count      int
	windowEnds time.Time
}

// NewAttemptLimiter создаёт ограничитель.
func NewAttemptLimiter() *AttemptLimiter {
	return &AttemptLimiter{now: time.Now, windows: make(map[string]attemptWindowState)}
}

// Allow сообщает, можно ли резиденту сделать ещё одну попытку, и засчитывает её.
//
// Пустой ключ пропускается без счёта: попасть сюда без личности можно только
// при ошибке сборки роутера, и отказывать в такой ситуации всем подряд —
// не то поведение, которое нужно.
func (l *AttemptLimiter) Allow(user string) bool {
	if l == nil || user == "" {
		return true
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.windows) >= maxAttemptEntries {
		// Чистим целиком, а не выборочно: перебирать таблицу под мьютексом на
		// каждой попытке дороже, чем раз в жизни начать её заново.
		clear(l.windows)
	}

	state, ok := l.windows[user]
	if !ok || !now.Before(state.windowEnds) {
		l.windows[user] = attemptWindowState{count: 1, windowEnds: now.Add(attemptWindow)}
		return true
	}
	if state.count >= maxAttempts {
		return false
	}
	state.count++
	l.windows[user] = state
	return true
}
