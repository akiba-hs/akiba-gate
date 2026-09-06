package nextcloud_test

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/nextcloud"
)

func ident() nextcloud.Identity {
	return nextcloud.Identity{UID: "tg42", DisplayName: "Алиса Иванова", Username: "alice"}
}

// other — разные люди. Нужны там, где важен объём хранилища: код одного и
// того же человека вытесняет его предыдущий, и одинаковые личности дали бы
// хранилище из одной записи.
func other(i int) nextcloud.Identity {
	id := strconv.Itoa(i)
	return nextcloud.Identity{UID: "tg" + id, DisplayName: "Житель " + id, Username: "u" + id}
}

func TestCodeRoundTrip(t *testing.T) {
	c := nextcloud.NewCodes()

	code, _, err := c.Issue(ident(), "192.168.8.5", false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := c.Redeem(code, "", "192.168.8.5")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if got.UID != "tg42" || got.DisplayName != "Алиса Иванова" {
		t.Fatalf("получено %+v", got)
	}
}

// Главное требование: код одноразовый. Второй обмен обязан провалиться —
// иначе перехваченный код работал бы столько раз, сколько его предъявят.
func TestCodeIsSingleUse(t *testing.T) {
	c := nextcloud.NewCodes()
	code, _, _ := c.Issue(ident(), "", false)

	if _, err := c.Redeem(code, "", ""); err != nil {
		t.Fatalf("первый обмен: %v", err)
	}
	if _, err := c.Redeem(code, "", ""); !errors.Is(err, nextcloud.ErrUnknownCode) {
		t.Fatalf("повторный обмен прошёл или дал не ту ошибку: %v", err)
	}
}

// Гонка двух одновременных обменов одного кода: успешным обязан быть ровно
// один. Иначе «одноразовость» держалась бы на удаче планировщика.
func TestCodeSurvivesConcurrentRedeem(t *testing.T) {
	c := nextcloud.NewCodes()
	code, _, _ := c.Issue(ident(), "", false)

	const racers = 32
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := c.Redeem(code, "", ""); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if success != 1 {
		t.Fatalf("успешных обменов %d, ожидался ровно один", success)
	}
}

func TestCodeExpires(t *testing.T) {
	c := nextcloud.NewCodes()
	now := nextcloud.SetClockForTest(c)

	code, _, _ := c.Issue(ident(), "", false)
	now.Advance(nextcloud.CodeTTLForTest + 1)

	if _, err := c.Redeem(code, "", ""); !errors.Is(err, nextcloud.ErrUnknownCode) {
		t.Fatalf("просроченный код принят: %v", err)
	}
}

// Код, выданный чуть раньше срока, обязан работать: иначе медленный редирект
// ломал бы вход на ровном месте.
func TestCodeWorksJustBeforeExpiry(t *testing.T) {
	c := nextcloud.NewCodes()
	now := nextcloud.SetClockForTest(c)

	code, _, _ := c.Issue(ident(), "", false)
	now.Advance(nextcloud.CodeTTLForTest - 1)

	if _, err := c.Redeem(code, "", ""); err != nil {
		t.Fatalf("код отвергнут до истечения срока: %v", err)
	}
}

// Привязка к flow: код, предъявленный с другого адреса, не работает.
func TestCodeIsBoundToClient(t *testing.T) {
	c := nextcloud.NewCodes()
	code, _, _ := c.Issue(ident(), "192.168.8.5", false)

	if _, err := c.Redeem(code, "", "10.0.0.1"); !errors.Is(err, nextcloud.ErrWrongClient) {
		t.Fatalf("код принят с чужого адреса: %v", err)
	}
}

// Неудачная попытка обязана сжигать код: иначе у атакующего оставалась бы
// целая минута на новые попытки с тем же кодом.
func TestFailedBindingBurnsCode(t *testing.T) {
	c := nextcloud.NewCodes()
	code, _, _ := c.Issue(ident(), "192.168.8.5", false)

	_, _ = c.Redeem(code, "", "10.0.0.1")

	if _, err := c.Redeem(code, "", "192.168.8.5"); !errors.Is(err, nextcloud.ErrUnknownCode) {
		t.Fatalf("код пережил неудачную попытку: %v", err)
	}
}

// Пустой адрес при выдаче означает выключенную привязку — тогда сверять нечего.
func TestCodeWithoutBindingIgnoresClient(t *testing.T) {
	c := nextcloud.NewCodes()
	code, _, _ := c.Issue(ident(), "", false)

	if _, err := c.Redeem(code, "", "10.0.0.1"); err != nil {
		t.Fatalf("код с выключенной привязкой отвергнут: %v", err)
	}
}

func TestUnknownCodeRejected(t *testing.T) {
	c := nextcloud.NewCodes()
	if _, err := c.Redeem("такого-кода-не-было", "", ""); !errors.Is(err, nextcloud.ErrUnknownCode) {
		t.Fatalf("выдуманный код принят: %v", err)
	}
}

// Код должен быть длинным и непредсказуемым: 32 байта дают 43 символа
// base64url. Заодно убеждаемся, что два подряд не совпадают.
func TestCodesAreRandomAndLong(t *testing.T) {
	c := nextcloud.NewCodes()
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, _, err := c.Issue(other(i), "", false)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if len(code) < 43 {
			t.Fatalf("код длиной %d символов слишком короткий: %q", len(code), code)
		}
		if strings.ContainsAny(code, "+/=") {
			t.Fatalf("код не в base64url и попадёт в адрес искажённым: %q", code)
		}
		if seen[code] {
			t.Fatalf("код повторился: %q", code)
		}
		seen[code] = true
	}
}

// Telegram-ID в код попадать не должен — ни в каком виде.
//
// Проверять одним поиском подстроки мало: код в base64, и «оптимизация» вида
// base64(telegramID) прошла бы такую проверку с честным видом. Поэтому
// раскодируем обратно и убеждаемся, что внутри ровно случайные байты, а два
// кода одной и той же личности не совпадают.
func TestCodeDoesNotLeakIdentity(t *testing.T) {
	c := nextcloud.NewCodes()
	id := nextcloud.Identity{UID: "tg270369579", DisplayName: "Bogdan", Username: "ilvesbogdan"}

	first, _, _ := c.Issue(id, "", false)
	second, _, _ := c.Issue(id, "", false)

	if first == second {
		t.Fatal("два кода одной личности совпали — код выводится из неё")
	}
	for _, code := range []string{first, second} {
		raw, err := base64.RawURLEncoding.DecodeString(code)
		if err != nil {
			t.Fatalf("код не декодируется: %v", err)
		}
		if len(raw) != 32 {
			t.Fatalf("в коде %d байт, ожидалось 32 случайных", len(raw))
		}
		for _, secret := range []string{"270369579", "ilvesbogdan", "Bogdan"} {
			if strings.Contains(code, secret) || strings.Contains(string(raw), secret) {
				t.Fatalf("в коде видно %q", secret)
			}
		}
	}
}

// Привязка к браузеру: без правильного nonce код не обменивается. Это защита
// от того, что резидент получит код на свой аккаунт и заставит чужой браузер
// открыть ссылку с ним.
func TestCodeRequiresNonceWhenBound(t *testing.T) {
	c := nextcloud.NewCodes()
	code, nonce, err := c.Issue(ident(), "", true)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if nonce == "" {
		t.Fatal("nonce не выдан при включённой привязке")
	}

	if _, err := c.Redeem(code, "чужой-nonce", ""); !errors.Is(err, nextcloud.ErrWrongClient) {
		t.Fatalf("код обменян с чужим nonce: %v", err)
	}
}

// Пустой nonce не должен подходить к привязанному коду: хеш пустой строки —
// такой же законный хеш, и без отдельного признака привязки он бы совпал.
func TestBoundCodeRejectsEmptyNonce(t *testing.T) {
	c := nextcloud.NewCodes()
	code, _, _ := c.Issue(ident(), "", true)

	if _, err := c.Redeem(code, "", ""); !errors.Is(err, nextcloud.ErrWrongClient) {
		t.Fatalf("привязанный код обменян с пустым nonce: %v", err)
	}
}

func TestBoundCodeAcceptsItsNonce(t *testing.T) {
	c := nextcloud.NewCodes()
	code, nonce, _ := c.Issue(ident(), "", true)

	got, err := c.Redeem(code, nonce, "")
	if err != nil {
		t.Fatalf("свой nonce отвергнут: %v", err)
	}
	if got.UID != "tg42" {
		t.Fatalf("получено %+v", got)
	}
}

// Один резидент не должен лишать входа всех остальных: новый код вытесняет
// его же прошлый, поэтому забить хранилище одним аккаунтом невозможно.
func TestIssueEvictsPreviousCodeOfSameUser(t *testing.T) {
	c := nextcloud.NewCodes()

	first, _, _ := c.Issue(ident(), "", false)
	second, _, _ := c.Issue(ident(), "", false)

	if c.Len() != 1 {
		t.Fatalf("в хранилище %d кодов, ожидался один", c.Len())
	}
	if _, err := c.Redeem(first, "", ""); !errors.Is(err, nextcloud.ErrUnknownCode) {
		t.Fatalf("прошлый код всё ещё действует: %v", err)
	}
	if _, err := c.Redeem(second, "", ""); err != nil {
		t.Fatalf("свежий код не работает: %v", err)
	}
}

// Вытеснение не должно задевать чужие коды.
func TestIssueKeepsCodesOfOtherUsers(t *testing.T) {
	c := nextcloud.NewCodes()

	alice, _, _ := c.Issue(ident(), "", false)
	_, _, _ = c.Issue(other(7), "", false)

	if _, err := c.Redeem(alice, "", ""); err != nil {
		t.Fatalf("чужая выдача погасила код: %v", err)
	}
}

// Просроченные записи не должны копиться: хранилище живёт всё время работы
// шлюза, и брошенные коды заняли бы память навсегда.
func TestExpiredCodesAreSwept(t *testing.T) {
	c := nextcloud.NewCodes()
	now := nextcloud.SetClockForTest(c)

	for i := 0; i < 50; i++ {
		if _, _, err := c.Issue(other(i), "", false); err != nil {
			t.Fatalf("Issue: %v", err)
		}
	}
	if c.Len() != 50 {
		t.Fatalf("в хранилище %d кодов, ожидалось 50", c.Len())
	}

	now.Advance(nextcloud.CodeTTLForTest + 1)
	if got := c.Len(); got != 0 {
		t.Fatalf("после истечения срока осталось %d кодов", got)
	}
}

// Хранилище ограничено сверху: иначе скрипт резидента раздул бы память.
func TestStoreIsCapped(t *testing.T) {
	c := nextcloud.NewCodes()
	var lastErr error
	for i := 0; i < nextcloud.MaxCodesForTest+10; i++ {
		if _, _, err := c.Issue(other(i), "", false); err != nil {
			lastErr = err
			break
		}
	}
	if !errors.Is(lastErr, nextcloud.ErrTooManyCodes) {
		t.Fatalf("потолок не сработал, последняя ошибка: %v", lastErr)
	}
	if c.Len() > nextcloud.MaxCodesForTest {
		t.Fatalf("в хранилище %d кодов при потолке %d", c.Len(), nextcloud.MaxCodesForTest)
	}
}
