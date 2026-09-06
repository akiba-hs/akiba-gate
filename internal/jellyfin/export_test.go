package jellyfin

import "time"

// Крючки для тестов. Файл с суффиксом _test.go в собранный бинарник не
// попадает, поэтому подменить часы снаружи в работающем шлюзе невозможно.

// AttemptWindowForTest — длина окна ограничителя попыток.
const AttemptWindowForTest = attemptWindow

// AdvanceAttemptsForTest двигает часы ограничителя вперёд: ждать реальную
// минуту в тесте недопустимо.
func AdvanceAttemptsForTest(l *AttemptLimiter, d time.Duration) {
	l.mu.Lock()
	base := l.now
	l.now = func() time.Time { return base().Add(d) }
	l.mu.Unlock()
}
