package jellyfin_test

import (
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/jellyfin"
)

// Код быстрого подключения — шесть цифр. Без ограничения их перебирает
// скрипт, и каждое попадание подтверждает чужой ожидающий вход.
func TestAttemptLimiterStopsBruteForce(t *testing.T) {
	l := jellyfin.NewAttemptLimiter()

	var allowed int
	for i := 0; i < 100; i++ {
		if l.Allow("tg42") {
			allowed++
		}
	}
	if allowed >= 100 {
		t.Fatal("перебор не ограничен")
	}
	if allowed == 0 {
		t.Fatal("не разрешена ни одна попытка")
	}
	if l.Allow("tg42") {
		t.Fatal("после исчерпания нормы попытка всё же разрешена")
	}
}

// Норма персональная: иначе один резидент, исчерпав её, закрыл бы вход всем.
func TestAttemptLimiterIsPerResident(t *testing.T) {
	l := jellyfin.NewAttemptLimiter()
	for i := 0; i < 100; i++ {
		l.Allow("tg42")
	}

	if !l.Allow("tg43") {
		t.Fatal("исчерпанная норма одного закрыла вход другому")
	}
}

// Норма восстанавливается: человек, ошибшийся в коде, не должен остаться без
// входа навсегда.
func TestAttemptLimiterRecoversAfterWindow(t *testing.T) {
	l := jellyfin.NewAttemptLimiter()
	for i := 0; i < 100; i++ {
		l.Allow("tg42")
	}
	if l.Allow("tg42") {
		t.Fatal("норма не исчерпана — тест бессмысленен")
	}

	jellyfin.AdvanceAttemptsForTest(l, jellyfin.AttemptWindowForTest+1)

	if !l.Allow("tg42") {
		t.Fatal("норма не восстановилась после окна")
	}
}

// Отсутствие ограничителя не должно ронять обработчик.
func TestNilAttemptLimiterAllows(t *testing.T) {
	var l *jellyfin.AttemptLimiter
	if !l.Allow("tg42") {
		t.Fatal("nil-ограничитель отказал")
	}
}

// Без личности считать некого: попасть сюда без неё можно только при ошибке
// сборки роутера, и отказывать в этом случае всем подряд неверно.
func TestAttemptLimiterIgnoresEmptyUser(t *testing.T) {
	l := jellyfin.NewAttemptLimiter()
	for i := 0; i < 100; i++ {
		if !l.Allow("") {
			t.Fatal("пустой ключ попал под ограничение")
		}
	}
}
