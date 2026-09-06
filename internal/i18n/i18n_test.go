package i18n_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/i18n"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// write кладёт содержимое в файл и сдвигает время изменения вперёд.
//
// Сдвиг обязателен: файловые системы хранят mtime с секундной точностью, а
// тест переписывает файл за миллисекунды — без сдвига изменение осталось бы
// незамеченным, и тест проверял бы не то, что нужно.
func write(t *testing.T, path, body string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("запись %s: %v", path, err)
	}
	stamp := time.Now().Add(age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("отметка времени %s: %v", path, err)
	}
}

func newBundle(t *testing.T) (*i18n.Bundle, string, func(time.Duration)) {
	t.Helper()
	path := testsupport.WriteMessages(t, testsupport.Messages())
	b, err := i18n.Load(path, time.Minute, quietLog())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	now := time.Now()
	b.SetClock(func() time.Time { return now })
	return b, path, func(d time.Duration) { now = now.Add(d) }
}

func TestLoadRejectsMissingFile(t *testing.T) {
	_, err := i18n.Load(filepath.Join(t.TempDir(), "нет.json"), time.Minute, quietLog())
	if err == nil {
		t.Fatal("отсутствующий файл принят; сервис поднялся бы без текстов")
	}
}

// Неполный файл на старте — отказ: откатываться в этот момент не на что.
func TestLoadRejectsIncompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "i18n.json")
	write(t, path, `{"portal_title":"Только заголовок"}`, 0)

	if _, err := i18n.Load(path, time.Minute, quietLog()); err == nil {
		t.Fatal("файл без обязательных полей принят")
	}
}

// Опечатка в имени поля оставила бы в интерфейсе пустую строку, поэтому
// незнакомые поля отвергаются целиком.
func TestLoadRejectsUnknownFields(t *testing.T) {
	m := testsupport.Messages()
	data, _ := json.Marshal(m)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	raw["portal_titel"] = "опечатка"
	broken, _ := json.Marshal(raw)

	path := filepath.Join(t.TempDir(), "i18n.json")
	write(t, path, string(broken), 0)

	if _, err := i18n.Load(path, time.Minute, quietLog()); err == nil {
		t.Fatal("файл с незнакомым полем принят")
	}
}

// Внутри TTL файл не читается вовсе — даже если он изменился.
func TestBundleKeepsCacheWithinTTL(t *testing.T) {
	b, path, _ := newBundle(t)

	m := testsupport.Messages()
	m.PortalTitle = "Новый заголовок"
	data, _ := json.Marshal(m)
	write(t, path, string(data), time.Hour)

	if got := b.Messages().PortalTitle; got != testsupport.Messages().PortalTitle {
		t.Fatalf("заголовок = %q, внутри TTL файл читаться не должен", got)
	}
}

func TestBundleRereadsChangedFileAfterTTL(t *testing.T) {
	b, path, advance := newBundle(t)

	m := testsupport.Messages()
	m.PortalTitle = "Новый заголовок"
	data, _ := json.Marshal(m)
	write(t, path, string(data), time.Hour)
	advance(2 * time.Minute)

	if got := b.Messages().PortalTitle; got != "Новый заголовок" {
		t.Fatalf("заголовок = %q, ожидался обновлённый", got)
	}
}

// Файл не менялся — перечитывать нечего, и время проверки должно сдвинуться,
// иначе каждый следующий запрос снова шёл бы на диск.
func TestBundleDoesNotRereadUnchangedFile(t *testing.T) {
	b, path, advance := newBundle(t)
	advance(2 * time.Minute)
	_ = b.Messages()

	// Портим файл, не трогая отметку времени: если бы шлюз читал его снова,
	// он бы это заметил.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.WriteFile(path, []byte("сломано"), 0o644); err != nil {
		t.Fatalf("порча файла: %v", err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("возврат отметки времени: %v", err)
	}
	advance(2 * time.Minute)

	if got := b.Messages().PortalTitle; got != testsupport.Messages().PortalTitle {
		t.Fatalf("заголовок = %q, файл с прежней отметкой перечитывать не следует", got)
	}
}

// Испорченный файл не должен доходить до резидента: отдаём прежние тексты
// и чиним файл ими же.
func TestBundleRestoresBrokenFile(t *testing.T) {
	b, path, advance := newBundle(t)
	write(t, path, "{это не json", time.Hour)
	advance(2 * time.Minute)

	if got := b.Messages().PortalTitle; got != testsupport.Messages().PortalTitle {
		t.Fatalf("заголовок = %q, ожидались прежние тексты", got)
	}

	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение восстановленного файла: %v", err)
	}
	var m i18n.Messages
	if err := json.Unmarshal(restored, &m); err != nil {
		t.Fatalf("восстановленный файл не разбирается: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("восстановленный файл неполон: %v", err)
	}
}

// После восстановления отметка времени обязана обновиться: запись меняет
// mtime, и без этого следующая проверка снова считала бы файл изменившимся.
func TestBundleDoesNotLoopAfterRestore(t *testing.T) {
	var logs strings.Builder
	path := testsupport.WriteMessages(t, testsupport.Messages())
	b, err := i18n.Load(path, time.Minute, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	now := time.Now()
	b.SetClock(func() time.Time { return now })

	write(t, path, "{сломано", time.Hour)
	now = now.Add(2 * time.Minute)
	_ = b.Messages()

	before := logs.String()
	now = now.Add(2 * time.Minute)
	_ = b.Messages()

	if strings.Count(logs.String(), "восстановлен") > strings.Count(before, "восстановлен") {
		t.Fatal("файл восстанавливается повторно: отметка времени после записи не обновлена")
	}
}

// Неполный файл в работе так же недопустим, как и на старте, — но здесь есть
// на что откатиться.
func TestBundleRejectsIncompleteUpdate(t *testing.T) {
	b, path, advance := newBundle(t)
	write(t, path, `{"portal_title":"Только заголовок"}`, time.Hour)
	advance(2 * time.Minute)

	if got := b.Messages().LoginButton; got != testsupport.Messages().LoginButton {
		t.Fatalf("кнопка входа = %q, ожидался откат на прежние тексты", got)
	}
}
