package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNoResident — такого резидента в базе нет.
var ErrNoResident = errors.New("audit: резидент не найден")

// Resident — человек, которого шлюз когда-либо видел авторизованным.
//
// Заводится не администратором вручную, а самим фактом входа: список
// резидентов живёт в Telegram, и дублировать его руками значило бы обречь
// себя на вечное расхождение двух списков.
type Resident struct {
	TelegramID string
	Username   string
	FirstName  string
	LastName   string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	// Services — идентификаторы доступных сервисов. Заполняется только
	// выборками, которые их запрашивают.
	Services []string
}

// DisplayName собирает имя для показа так же, как это делает auth.Claims:
// имя с фамилией, иначе ник, иначе идентификатор.
func (r Resident) DisplayName() string {
	switch {
	case r.FirstName != "" && r.LastName != "":
		return r.FirstName + " " + r.LastName
	case r.FirstName != "":
		return r.FirstName
	case r.LastName != "":
		return r.LastName
	case r.Username != "":
		return "@" + r.Username
	default:
		return "tg" + r.TelegramID
	}
}

// UpsertResident заводит резидента или обновляет его данные.
//
// created_at сохраняется намеренно: он показывает, когда человек впервые
// появился в системе, и перезаписывать его при каждом входе значило бы
// потерять единственный ответ на вопрос «давно ли он с нами».
//
// Права доступа здесь не трогаются вовсе: вход не должен ни давать, ни
// отнимать сервисы. Их раздаёт только администратор.
func (s *Store) UpsertResident(ctx context.Context, r Resident) error {
	now := s.now().Unix()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO residents (tg_id, username, first_name, last_name, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(tg_id) DO UPDATE SET
    username   = excluded.username,
    first_name = excluded.first_name,
    last_name  = excluded.last_name,
    updated_at = excluded.updated_at;`,
		r.TelegramID, r.Username, r.FirstName, r.LastName, now, now)
	if err != nil {
		return fmt.Errorf("audit: сохранение резидента: %w", err)
	}
	return nil
}

// Residents возвращает всех резидентов вместе с их правами, по имени.
//
// Права подтягиваются одним отдельным запросом, а не подзапросом на каждого:
// резидентов десятки, но соединение к SQLite одно, и N+1 здесь означал бы
// N+1 блокировок базы на каждое открытие админки.
func (s *Store) Residents(ctx context.Context) ([]Resident, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT tg_id, username, first_name, last_name, created_at, updated_at
FROM residents
ORDER BY first_name COLLATE NOCASE, last_name COLLATE NOCASE, username COLLATE NOCASE, tg_id;`)
	if err != nil {
		return nil, fmt.Errorf("audit: выборка резидентов: %w", err)
	}
	defer rows.Close()

	var out []Resident
	index := make(map[string]int)
	for rows.Next() {
		var (
			r                Resident
			created, updated int64
		)
		if err := rows.Scan(&r.TelegramID, &r.Username, &r.FirstName, &r.LastName,
			&created, &updated); err != nil {
			return nil, fmt.Errorf("audit: чтение резидента: %w", err)
		}
		r.CreatedAt = time.Unix(created, 0).UTC()
		r.UpdatedAt = time.Unix(updated, 0).UTC()
		index[r.TelegramID] = len(out)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: выборка резидентов: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}

	grants, err := s.db.QueryContext(ctx,
		`SELECT tg_id, service FROM resident_services ORDER BY service;`)
	if err != nil {
		return nil, fmt.Errorf("audit: выборка прав: %w", err)
	}
	defer grants.Close()
	for grants.Next() {
		var id, service string
		if err := grants.Scan(&id, &service); err != nil {
			return nil, fmt.Errorf("audit: чтение права: %w", err)
		}
		if i, ok := index[id]; ok {
			out[i].Services = append(out[i].Services, service)
		}
	}
	return out, grants.Err()
}

// ResidentServices возвращает идентификаторы сервисов, доступных человеку.
//
// Неизвестный резидент — это пустой список, а не ошибка: право «ничего» и
// «его тут нет» для проверки доступа означают одно и то же, а отдельная
// ошибка заставила бы каждого вызывающего решать, что с ней делать.
func (s *Store) ResidentServices(ctx context.Context, telegramID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT service FROM resident_services WHERE tg_id = ? ORDER BY service;`, telegramID)
	if err != nil {
		return nil, fmt.Errorf("audit: выборка прав: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var service string
		if err := rows.Scan(&service); err != nil {
			return nil, fmt.Errorf("audit: чтение права: %w", err)
		}
		out = append(out, service)
	}
	return out, rows.Err()
}

// SetResidentServices заменяет набор прав целиком.
//
// Целиком, а не по одному: админка присылает состояние всех галочек разом, и
// раздельные «выдать»/«отнять» на той же форме означали бы, что снятая
// галочка, потерянная по дороге, тихо оставит доступ.
//
// Резидент обязан существовать: права без человека — мусор, который никогда
// не будет виден в админке и никогда не будет вычищен.
func (s *Store) SetResidentServices(ctx context.Context, telegramID string, services []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: смена прав: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM residents WHERE tg_id = ?;`, telegramID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoResident
	}
	if err != nil {
		return fmt.Errorf("audit: проверка резидента: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM resident_services WHERE tg_id = ?;`, telegramID); err != nil {
		return fmt.Errorf("audit: очистка прав: %w", err)
	}
	for _, service := range services {
		if service == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO resident_services (tg_id, service) VALUES (?, ?);`,
			telegramID, service); err != nil {
			return fmt.Errorf("audit: выдача права %q: %w", service, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE residents SET updated_at = ? WHERE tg_id = ?;`, s.now().Unix(), telegramID); err != nil {
		return fmt.Errorf("audit: отметка времени: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: смена прав: %w", err)
	}
	return nil
}

// DeleteResident убирает человека вместе с его правами.
//
// Права уходят каскадом (внешний ключ в схеме): иначе выданные когда-то
// сервисы вернулись бы к человеку сами, если он снова появится в чате.
func (s *Store) DeleteResident(ctx context.Context, telegramID string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM residents WHERE tg_id = ?;`, telegramID); err != nil {
		return fmt.Errorf("audit: удаление резидента: %w", err)
	}
	return nil
}
