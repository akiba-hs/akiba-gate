// Пакет audit хранит состояние шлюза, которое обязано пережить перезапуск.
//
// Это список резидентов и выданные им права на сервисы. Список наполняется
// входами (человек авторизовался — значит он есть), права раздаёт
// администратор, а чистит список бот по составу группового чата.
//
// Чего здесь намеренно нет.
//
// Истории добавления торрентов: её пишет бот в групповой чат. Чат читают,
// базу — нет, и вторая копия только расходилась бы с первой.
//
// Паролей Nextcloud: вход туда идёт одноразовым кодом (см. internal/nextcloud),
// и пароль резидента шлюзу не известен вовсе. Хранить нечего.
//
// Таблицы, которые эти данные держали, удаляются миграцией ниже.
package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // чистый Go-драйвер: сборка без cgo
)

// Store — состояние шлюза в SQLite.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

const schema = `
-- Резиденты. Ключ — Telegram-ID: ник человек может сменить в любой момент,
-- и тогда он «потерял» бы вместе с ним все выданные права.
CREATE TABLE IF NOT EXISTS residents (
    tg_id      TEXT    PRIMARY KEY,
    username   TEXT    NOT NULL DEFAULT '',
    first_name TEXT    NOT NULL DEFAULT '',
    last_name  TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Выданные права. Пары «человек — сервис»; отсутствие строки означает запрет.
-- Каскад обязателен: иначе выбывший из чата резидент, вернувшись, получил бы
-- назад все свои старые права молча.
CREATE TABLE IF NOT EXISTS resident_services (
    tg_id   TEXT NOT NULL REFERENCES residents(tg_id) ON DELETE CASCADE,
    service TEXT NOT NULL,
    PRIMARY KEY (tg_id, service)
);

-- Таблицы, которых в этой схеме быть не должно (см. шапку пакета). DROP
-- оставлены в схеме навсегда, а не выполнены разово руками: баз у нас две —
-- боевая и локальная, — и пропущенный DROP означал бы таблицу, которую никто
-- не пишет и не читает, но которая лежит в файле и путает при разборе.
--
-- В nextcloud_users вдобавок лежали пароли: оставить их значило бы хранить
-- секреты, которые ничему не служат.
DROP TABLE IF EXISTS torrent_events;
DROP TABLE IF EXISTS nextcloud_users;
`

// Open открывает (и при необходимости создаёт) базу шлюза.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("audit: не удалось создать каталог БД: %w", err)
		}
	}
	// WAL — чтобы читатели и писатели не блокировали друг друга.
	// busy_timeout — чтобы редкие пересечения записей ждали, а не падали.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: открытие БД: %w", err)
	}
	// SQLite не любит параллельные писатели: один коннект снимает целый класс
	// ошибок "database is locked".
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: миграция схемы: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

// Close закрывает базу.
func (s *Store) Close() error { return s.db.Close() }
