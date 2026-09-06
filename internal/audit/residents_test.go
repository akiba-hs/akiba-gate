package audit_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/audit"
)

func alice() audit.Resident {
	return audit.Resident{TelegramID: "1", Username: "alice", FirstName: "Алиса", LastName: "Иванова"}
}

func bob() audit.Resident {
	return audit.Resident{TelegramID: "2", Username: "bob", FirstName: "Борис", LastName: "Петров"}
}

func TestUpsertAndListResidents(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if err := s.UpsertResident(ctx, alice()); err != nil {
		t.Fatalf("UpsertResident: %v", err)
	}
	if err := s.UpsertResident(ctx, bob()); err != nil {
		t.Fatalf("UpsertResident: %v", err)
	}

	list, err := s.Residents(ctx)
	if err != nil {
		t.Fatalf("Residents: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("получено %d резидентов: %+v", len(list), list)
	}
	// Порядок по имени: Алиса раньше Бориса.
	if list[0].Username != "alice" || list[1].Username != "bob" {
		t.Fatalf("список не отсортирован по имени: %+v", list)
	}
	if list[0].DisplayName() != "Алиса Иванова" {
		t.Fatalf("имя = %q", list[0].DisplayName())
	}
}

// Повторный вход не должен плодить записи, но обязан обновлять данные:
// человек мог сменить ник или фамилию.
func TestUpsertResidentUpdatesInPlace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertResident(ctx, alice()); err != nil {
		t.Fatalf("UpsertResident: %v", err)
	}

	renamed := alice()
	renamed.Username = "alice_new"
	renamed.LastName = "Сидорова"
	if err := s.UpsertResident(ctx, renamed); err != nil {
		t.Fatalf("повторный UpsertResident: %v", err)
	}

	list, _ := s.Residents(ctx)
	if len(list) != 1 {
		t.Fatalf("создан дубликат: %+v", list)
	}
	if list[0].Username != "alice_new" || list[0].LastName != "Сидорова" {
		t.Fatalf("данные не обновлены: %+v", list[0])
	}
}

// Вход не должен ни давать, ни отнимать права: их раздаёт только админка.
func TestUpsertResidentKeepsServices(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertResident(ctx, alice()); err != nil {
		t.Fatalf("UpsertResident: %v", err)
	}
	if err := s.SetResidentServices(ctx, "1", []string{"jellyfin", "nextcloud"}); err != nil {
		t.Fatalf("SetResidentServices: %v", err)
	}

	if err := s.UpsertResident(ctx, alice()); err != nil {
		t.Fatalf("повторный вход: %v", err)
	}

	got, _ := s.ResidentServices(ctx, "1")
	if len(got) != 2 {
		t.Fatalf("вход изменил права: %v", got)
	}
}

func TestSetResidentServicesReplacesWholeSet(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertResident(ctx, alice()); err != nil {
		t.Fatalf("UpsertResident: %v", err)
	}

	if err := s.SetResidentServices(ctx, "1", []string{"jellyfin", "qbittorrent"}); err != nil {
		t.Fatalf("выдача: %v", err)
	}
	// Снятая галочка обязана исчезнуть, а не остаться «на всякий случай».
	if err := s.SetResidentServices(ctx, "1", []string{"qbittorrent"}); err != nil {
		t.Fatalf("снятие: %v", err)
	}

	got, err := s.ResidentServices(ctx, "1")
	if err != nil {
		t.Fatalf("ResidentServices: %v", err)
	}
	if !slices.Equal(got, []string{"qbittorrent"}) {
		t.Fatalf("права = %v, ожидался только qbittorrent", got)
	}
}

func TestSetResidentServicesClearsAll(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.UpsertResident(ctx, alice())
	_ = s.SetResidentServices(ctx, "1", []string{"jellyfin"})

	if err := s.SetResidentServices(ctx, "1", nil); err != nil {
		t.Fatalf("очистка: %v", err)
	}
	got, _ := s.ResidentServices(ctx, "1")
	if len(got) != 0 {
		t.Fatalf("права остались: %v", got)
	}
}

// Права без человека — мусор: он никогда не будет виден в админке и никогда
// не будет вычищен.
func TestSetResidentServicesRejectsUnknownResident(t *testing.T) {
	s := newStore(t)
	err := s.SetResidentServices(context.Background(), "404", []string{"jellyfin"})
	if !errors.Is(err, audit.ErrNoResident) {
		t.Fatalf("ожидалась ErrNoResident, получено %v", err)
	}
}

// Неизвестный человек — это пустой список прав, а не ошибка: для проверки
// доступа «его тут нет» и «ему ничего не выдано» означают одно и то же.
func TestResidentServicesOfUnknownIsEmpty(t *testing.T) {
	s := newStore(t)
	got, err := s.ResidentServices(context.Background(), "404")
	if err != nil {
		t.Fatalf("ResidentServices: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("получено %v", got)
	}
}

// Права уходят вместе с человеком: иначе вернувшийся в чат резидент молча
// получил бы назад всё, что ему когда-то выдавали.
func TestDeleteResidentRemovesGrants(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.UpsertResident(ctx, alice())
	_ = s.SetResidentServices(ctx, "1", []string{"jellyfin", "nextcloud"})

	if err := s.DeleteResident(ctx, "1"); err != nil {
		t.Fatalf("DeleteResident: %v", err)
	}

	list, _ := s.Residents(ctx)
	if len(list) != 0 {
		t.Fatalf("резидент остался: %+v", list)
	}
	// Заводим того же человека заново — прав у него быть не должно.
	_ = s.UpsertResident(ctx, alice())
	got, _ := s.ResidentServices(ctx, "1")
	if len(got) != 0 {
		t.Fatalf("права вернулись вместе с человеком: %v", got)
	}
}

// Список для админки обязан приезжать вместе с правами: отдельный запрос на
// каждого означал бы N+1 обращений к базе с единственным соединением.
func TestResidentsCarryServices(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.UpsertResident(ctx, alice())
	_ = s.UpsertResident(ctx, bob())
	_ = s.SetResidentServices(ctx, "1", []string{"jellyfin", "qbittorrent"})

	list, err := s.Residents(ctx)
	if err != nil {
		t.Fatalf("Residents: %v", err)
	}
	byID := map[string][]string{}
	for _, r := range list {
		byID[r.TelegramID] = r.Services
	}
	if len(byID["1"]) != 2 {
		t.Fatalf("права Алисы = %v", byID["1"])
	}
	if len(byID["2"]) != 0 {
		t.Fatalf("Борису достались чужие права: %v", byID["2"])
	}
}

func TestResidentDisplayNameFallbacks(t *testing.T) {
	cases := []struct {
		name string
		in   audit.Resident
		want string
	}{
		{"имя и фамилия", audit.Resident{FirstName: "Алиса", LastName: "Иванова"}, "Алиса Иванова"},
		{"только имя", audit.Resident{FirstName: "Алиса"}, "Алиса"},
		{"только фамилия", audit.Resident{LastName: "Иванова"}, "Иванова"},
		{"только ник", audit.Resident{Username: "alice"}, "@alice"},
		{"ничего", audit.Resident{TelegramID: "42"}, "tg42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.DisplayName(); got != c.want {
				t.Fatalf("получено %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// Сбой базы посреди смены прав не должен оставить половину применённых
// галочек: вся замена идёт одной транзакцией.
func TestResidentWritesFailOnClosedDB(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertResident(ctx, alice()); err != nil {
		t.Fatalf("UpsertResident: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := s.SetResidentServices(ctx, "1", []string{"jellyfin"}); err == nil {
		t.Error("смена прав в закрытой базе прошла успешно")
	}
	if err := s.DeleteResident(ctx, "1"); err == nil {
		t.Error("удаление из закрытой базы прошло успешно")
	}
}

// Пустые строки в списке — не сервис, и в базу попадать не должны: там они
// стали бы правом, которое ничему не соответствует.
func TestSetResidentServicesSkipsEmptyValues(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.UpsertResident(ctx, alice())

	if err := s.SetResidentServices(ctx, "1", []string{"", "jellyfin", ""}); err != nil {
		t.Fatalf("SetResidentServices: %v", err)
	}
	got, _ := s.ResidentServices(ctx, "1")
	if !slices.Equal(got, []string{"jellyfin"}) {
		t.Fatalf("права = %v", got)
	}
}
