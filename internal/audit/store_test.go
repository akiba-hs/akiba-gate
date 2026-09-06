package audit_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/audit"

	_ "modernc.org/sqlite"
)

func newStore(t *testing.T) *audit.Store {
	t.Helper()
	s, err := audit.Open(filepath.Join(t.TempDir(), "sub", "gate.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Миграция: у боевой базы обе старые таблицы уже есть, и открытие обязано их
// убрать. Особенно nextcloud_users — там лежали пароли, которые перестали быть
// механизмом входа: оставить их значило бы хранить секреты без причины.
func TestOpenDropsLegacyTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate.db")

	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("создание старой базы: %v", err)
	}
	if _, err := old.Exec(`CREATE TABLE torrent_events (id INTEGER PRIMARY KEY, name TEXT);
	                       INSERT INTO torrent_events (name) VALUES ('Ubuntu');
	                       CREATE TABLE nextcloud_users (uid TEXT PRIMARY KEY, secret BLOB);
	                       INSERT INTO nextcloud_users VALUES ('tg1', x'00');`); err != nil {
		t.Fatalf("наполнение старой базы: %v", err)
	}
	_ = old.Close()

	s, err := audit.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("проверочное открытие: %v", err)
	}
	defer check.Close()
	for _, table := range []string{"torrent_events", "nextcloud_users"} {
		var name string
		err = check.QueryRow(
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?;`, table).Scan(&name)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("таблица %s не удалена (err = %v, name = %q)", table, err, name)
		}
	}
}

// Открыть базу по недоступному пути — ошибка запуска, а не молчаливая работа
// без сохранённых паролей.
func TestOpenFailsOnUnwritablePath(t *testing.T) {
	if _, err := audit.Open("/proc/недоступно/gate.db"); err == nil {
		t.Fatal("база открыта по заведомо недоступному пути")
	}
}

// Закрытая база обязана возвращать ошибку, а не пустой список прав: иначе
// сбой базы выглядел бы как «доступа нет» и молча запирал бы всех.
func TestStoreReportsErrorsOnClosedDB(t *testing.T) {
	s, err := audit.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx := context.Background()

	if _, err := s.ResidentServices(ctx, "1"); err == nil {
		t.Error("чтение прав из закрытой базы прошло успешно")
	}
	if _, err := s.Residents(ctx); err == nil {
		t.Error("чтение резидентов из закрытой базы прошло успешно")
	}
	if err := s.UpsertResident(ctx, alice()); err == nil {
		t.Error("запись в закрытую базу прошла успешно")
	}
}
