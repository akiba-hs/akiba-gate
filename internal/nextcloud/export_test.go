package nextcloud

import "time"

// Крючки для тестов. Отдельный файл с суффиксом _test.go: в собранный
// бинарник он не попадает, поэтому подменить часы или прочитать потолок
// снаружи пакета в работающем шлюзе невозможно.

// CodeTTLForTest — срок жизни кода.
const CodeTTLForTest = codeTTL

// MaxCodesForTest — потолок хранилища.
const MaxCodesForTest = maxCodes

// TestClock — управляемые часы.
type TestClock struct{ now time.Time }

// Advance двигает время вперёд.
func (c *TestClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// SetClockForTest подменяет источник времени в хранилище и возвращает часы.
// Ждать реальную минуту в тесте недопустимо.
func SetClockForTest(c *Codes) *TestClock {
	clock := &TestClock{now: time.Now()}
	c.now = func() time.Time { return clock.now }
	return clock
}
