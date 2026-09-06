package directory_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/audit"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/directory"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// memoryStore — список резидентов без базы.
type memoryStore struct {
	mu      sync.Mutex
	people  map[string]audit.Resident
	upserts int
	deletes []string
	err     error
}

func newStore(seed ...audit.Resident) *memoryStore {
	m := &memoryStore{people: map[string]audit.Resident{}}
	for _, r := range seed {
		m.people[r.TelegramID] = r
	}
	return m
}

func (m *memoryStore) UpsertResident(_ context.Context, r audit.Resident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.upserts++
	m.people[r.TelegramID] = r
	return nil
}

func (m *memoryStore) Residents(context.Context) ([]audit.Resident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	out := make([]audit.Resident, 0, len(m.people))
	for _, r := range m.people {
		out = append(out, r)
	}
	return out, nil
}

func (m *memoryStore) DeleteResident(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	delete(m.people, id)
	m.deletes = append(m.deletes, id)
	return nil
}

func (m *memoryStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.people)
}

func (m *memoryStore) writes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upserts
}

func (m *memoryStore) get(id string) (audit.Resident, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.people[id]
	return r, ok
}

func claims(id, username, first, last string) *auth.Claims {
	return &auth.Claims{
		TelegramID: id, Username: username,
		FirstName: first, LastName: last, IsResident: true,
	}
}

func TestRecorderStoresNewResident(t *testing.T) {
	store := newStore()
	rec := directory.NewRecorder(store, quiet())

	rec.Note(context.Background(), claims("1", "alice", "Алиса", "Иванова"))

	got, ok := store.get("1")
	if !ok {
		t.Fatal("резидент не записан")
	}
	if got.Username != "alice" || got.FirstName != "Алиса" {
		t.Fatalf("записано %+v", got)
	}
}

// Портал и прокси дёргаются десятки раз в минуту, а соединение к SQLite одно:
// писать на каждый запрос нельзя.
func TestRecorderWritesOnceForUnchangedData(t *testing.T) {
	store := newStore()
	rec := directory.NewRecorder(store, quiet())
	c := claims("1", "alice", "Алиса", "Иванова")

	for i := 0; i < 50; i++ {
		rec.Note(context.Background(), c)
	}

	if store.writes() != 1 {
		t.Fatalf("выполнено %d записей, ожидалась одна", store.writes())
	}
}

// А вот смена ника обязана доехать до базы сразу, а не ждать перезапуска.
func TestRecorderWritesAgainWhenDataChanges(t *testing.T) {
	store := newStore()
	rec := directory.NewRecorder(store, quiet())

	rec.Note(context.Background(), claims("1", "alice", "Алиса", "Иванова"))
	rec.Note(context.Background(), claims("1", "alice_new", "Алиса", "Сидорова"))

	if store.writes() != 2 {
		t.Fatalf("выполнено %d записей, ожидалось две", store.writes())
	}
	got, _ := store.get("1")
	if got.Username != "alice_new" || got.LastName != "Сидорова" {
		t.Fatalf("данные не обновлены: %+v", got)
	}
}

// Список — это список резидентов. Посторонний, заглянувший на портал, в нём
// не нужен: иначе админка заполнится случайными людьми из интернета.
func TestRecorderSkipsNonResidents(t *testing.T) {
	store := newStore()
	rec := directory.NewRecorder(store, quiet())

	rec.Note(context.Background(), &auth.Claims{TelegramID: "9", IsResident: false})

	if store.count() != 0 {
		t.Fatalf("записан не резидент: %d записей", store.count())
	}
}

func TestRecorderIgnoresAnonymous(t *testing.T) {
	store := newStore()
	rec := directory.NewRecorder(store, quiet())

	rec.Note(context.Background(), nil)
	rec.Note(context.Background(), &auth.Claims{IsResident: true}) // без Telegram-ID

	if store.count() != 0 {
		t.Fatalf("записано %d", store.count())
	}
}

// Сбой базы не должен ронять запрос: не пустить резидента из-за того, что не
// удалось обновить его фамилию, — плохой размен.
func TestRecorderSurvivesStoreFailure(t *testing.T) {
	store := newStore()
	store.err = errors.New("база недоступна")
	rec := directory.NewRecorder(store, quiet())

	rec.Note(context.Background(), claims("1", "alice", "Алиса", "Иванова"))

	// И повторяет попытку в следующий раз: неудачная запись не должна
	// запоминаться как успешная.
	store.mu.Lock()
	store.err = nil
	store.mu.Unlock()
	rec.Note(context.Background(), claims("1", "alice", "Алиса", "Иванова"))

	if _, ok := store.get("1"); !ok {
		t.Fatal("после починки базы резидент так и не записан")
	}
}

func TestRecorderIsSafeForConcurrentUse(t *testing.T) {
	store := newStore()
	rec := directory.NewRecorder(store, quiet())

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec.Note(context.Background(), claims("1", "alice", "Алиса", "Иванова"))
		}()
	}
	wg.Wait()

	if store.count() != 1 {
		t.Fatalf("записей %d", store.count())
	}
}

// fakeChat — состав группового чата без Telegram.
type fakeChat struct {
	mu      sync.Mutex
	status  map[string]tgnotify.Membership
	profile map[string]tgnotify.ChatMemberProfile
	err     map[string]error
	calls   int
}

func (f *fakeChat) ChatMember(_ context.Context, id string) (tgnotify.Membership, tgnotify.ChatMemberProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if err := f.err[id]; err != nil {
		return tgnotify.MembershipUnknown, tgnotify.ChatMemberProfile{}, err
	}
	return f.status[id], f.profile[id], nil
}

func person(id, username string) audit.Resident {
	return audit.Resident{TelegramID: id, Username: username, FirstName: "Имя" + id}
}

// Главное, ради чего сверка нужна: выбывший из чата исчезает из базы.
func TestReconcilerRemovesFormerMembers(t *testing.T) {
	store := newStore(person("1", "alice"), person("2", "bob"))
	chat := &fakeChat{status: map[string]tgnotify.Membership{
		"1": tgnotify.MembershipIn,
		"2": tgnotify.MembershipOut,
	}}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	if _, ok := store.get("2"); ok {
		t.Fatal("выбывший резидент остался в базе")
	}
	if _, ok := store.get("1"); !ok {
		t.Fatal("оставшийся резидент удалён")
	}
}

// Сверка не добавляет никого: Bot API не умеет отдавать список участников
// группы, и любое добавление было бы выдумкой.
func TestReconcilerNeverAddsAnyone(t *testing.T) {
	store := newStore(person("1", "alice"))
	chat := &fakeChat{status: map[string]tgnotify.Membership{"1": tgnotify.MembershipIn}}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	if store.count() != 1 {
		t.Fatalf("в базе стало %d резидентов", store.count())
	}
}

// Сбой связи — не повод объявлять человека выбывшим: иначе недоступность
// Telegram вычистила бы из базы вообще всех.
func TestReconcilerKeepsResidentOnError(t *testing.T) {
	store := newStore(person("1", "alice"))
	chat := &fakeChat{err: map[string]error{"1": errors.New("нет связи с Telegram")}}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	if _, ok := store.get("1"); !ok {
		t.Fatal("резидент удалён из-за сбоя связи")
	}
}

// Неизвестный статус — тоже «не знаем», и удалять по нему нельзя.
func TestReconcilerKeepsResidentOnUnknownStatus(t *testing.T) {
	store := newStore(person("1", "alice"))
	chat := &fakeChat{status: map[string]tgnotify.Membership{"1": tgnotify.MembershipUnknown}}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	if _, ok := store.get("1"); !ok {
		t.Fatal("резидент удалён по неизвестному статусу")
	}
}

// Администратора из конфигурации не удаляет ничто: сбой проверки не должен
// уносить единственного человека, способного раздавать доступ.
func TestReconcilerProtectsRootAdmin(t *testing.T) {
	store := newStore(person("270369579", "ilvesbogdan"))
	chat := &fakeChat{status: map[string]tgnotify.Membership{"270369579": tgnotify.MembershipOut}}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()),
		[]string{"270369579"}, quiet())

	r.Run(context.Background())

	if _, ok := store.get("270369579"); !ok {
		t.Fatal("администратор из конфигурации удалён")
	}
}

// Заодно сверка обновляет имена: человек мог смениться, пока не заходил.
func TestReconcilerUpdatesChangedProfiles(t *testing.T) {
	store := newStore(audit.Resident{TelegramID: "1", Username: "alice", FirstName: "Алиса"})
	chat := &fakeChat{
		status: map[string]tgnotify.Membership{"1": tgnotify.MembershipIn},
		profile: map[string]tgnotify.ChatMemberProfile{
			"1": {Username: "alice_new", FirstName: "Алиса", LastName: "Сидорова"},
		},
	}
	store2 := store
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	got, _ := store2.get("1")
	if got.Username != "alice_new" || got.LastName != "Сидорова" {
		t.Fatalf("данные не обновлены: %+v", got)
	}
}

// Пустой профиль Telegram отдаёт не всегда — затирать им известное имя нельзя.
func TestReconcilerIgnoresEmptyProfile(t *testing.T) {
	store := newStore(person("1", "alice"))
	chat := &fakeChat{
		status:  map[string]tgnotify.Membership{"1": tgnotify.MembershipIn},
		profile: map[string]tgnotify.ChatMemberProfile{"1": {}},
	}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	got, _ := store.get("1")
	if got.Username != "alice" {
		t.Fatalf("имя затёрто пустым профилем: %+v", got)
	}
}

// Неизменившийся профиль не должен вызывать запись в базу.
func TestReconcilerDoesNotWriteUnchangedProfiles(t *testing.T) {
	store := newStore(person("1", "alice"))
	chat := &fakeChat{
		status: map[string]tgnotify.Membership{"1": tgnotify.MembershipIn},
		profile: map[string]tgnotify.ChatMemberProfile{
			"1": {Username: "alice", FirstName: "Имя1"},
		},
	}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	if store.writes() != 0 {
		t.Fatalf("выполнено %d лишних записей", store.writes())
	}
}

// Открывают админку сколько угодно раз подряд; без паузы каждое обновление
// страницы означало бы обход всех резидентов и упор в лимиты Bot API.
func TestTriggerThrottlesRepeatedRuns(t *testing.T) {
	store := newStore(person("1", "alice"))
	chat := &fakeChat{status: map[string]tgnotify.Membership{"1": tgnotify.MembershipIn}}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	started := 0
	for i := 0; i < 10; i++ {
		if r.Trigger(context.Background()) {
			started++
		}
	}

	if started != 1 {
		t.Fatalf("сверка запущена %d раз, ожидался один", started)
	}
}

// Сверка идёт в фоне и переживает завершение запроса: страница админки
// отдаётся раньше, чем она закончится.
func TestTriggerOutlivesRequestContext(t *testing.T) {
	store := newStore(person("1", "alice"), person("2", "bob"))
	chat := &fakeChat{status: map[string]tgnotify.Membership{
		"1": tgnotify.MembershipIn,
		"2": tgnotify.MembershipOut,
	}}
	r := directory.NewReconciler(store, chat, directory.NewRecorder(store, quiet()), nil, quiet())

	ctx, cancel := context.WithCancel(context.Background())
	if !r.Trigger(ctx) {
		t.Fatal("сверка не запустилась")
	}
	cancel() // запрос завершился, страница ушла резиденту

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := store.get("2"); !ok {
			return // сверка доработала несмотря на отменённый контекст
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("сверка оборвалась вместе с запросом")
}

// Без бота сверять состав не с чем.
func TestTriggerDoesNothingWithoutChat(t *testing.T) {
	r := directory.NewReconciler(newStore(), nil, nil, nil, quiet())
	if r.Trigger(context.Background()) {
		t.Fatal("сверка запустилась без бота")
	}
}

// Вернувшийся в чат человек обязан записаться заново. Без сброса памяти
// регистратора он оставался бы невидимым для админки до перезапуска шлюза.
func TestForgetAllowsReturningResident(t *testing.T) {
	store := newStore()
	rec := directory.NewRecorder(store, quiet())
	c := claims("1", "alice", "Алиса", "Иванова")

	rec.Note(context.Background(), c)
	_ = store.DeleteResident(context.Background(), "1")
	rec.Forget("1")
	rec.Note(context.Background(), c)

	if _, ok := store.get("1"); !ok {
		t.Fatal("вернувшийся резидент не записан заново")
	}
}

// Предохранитель. Telegram умеет отвечать уверенно и неверно: неправильный
// TELEGRAM_CHAT_ID даёт «user not found» на каждого, то есть MembershipOut для
// всех. Одно открытие админки не должно стирать весь список — восстановить
// выданные права потом можно только руками.
func TestReconcilerRefusesMassDeletion(t *testing.T) {
	var seed []audit.Resident
	status := map[string]tgnotify.Membership{}
	for i := 0; i < 10; i++ {
		id := "u" + string(rune('0'+i))
		seed = append(seed, person(id, "user"+id))
		status[id] = tgnotify.MembershipOut // «чата не существует»
	}
	store := newStore(seed...)
	r := directory.NewReconciler(store, &fakeChat{status: status},
		directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	if store.count() != 10 {
		t.Fatalf("удалено %d резидентов из 10, ожидалось ноль", 10-store.count())
	}
}

// Обычное выбывание одного-двух человек предохранитель блокировать не должен:
// иначе список никогда бы не чистился.
func TestReconcilerAllowsSmallDeletion(t *testing.T) {
	var seed []audit.Resident
	status := map[string]tgnotify.Membership{}
	for i := 0; i < 10; i++ {
		id := "u" + string(rune('0'+i))
		seed = append(seed, person(id, "user"+id))
		status[id] = tgnotify.MembershipIn
	}
	status["u0"] = tgnotify.MembershipOut
	status["u1"] = tgnotify.MembershipOut

	store := newStore(seed...)
	r := directory.NewReconciler(store, &fakeChat{status: status},
		directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	if store.count() != 8 {
		t.Fatalf("в базе осталось %d резидентов, ожидалось 8", store.count())
	}
	if _, ok := store.get("u0"); ok {
		t.Error("выбывший резидент остался")
	}
}

// Решение «не удалять» принимается по всей пачке, а не по первым нескольким:
// иначе половина списка успела бы исчезнуть до срабатывания предохранителя.
func TestReconcilerDeletesNothingWhenTripped(t *testing.T) {
	var seed []audit.Resident
	status := map[string]tgnotify.Membership{}
	for i := 0; i < 8; i++ {
		id := "u" + string(rune('0'+i))
		seed = append(seed, person(id, "user"+id))
		status[id] = tgnotify.MembershipOut
	}
	store := newStore(seed...)
	r := directory.NewReconciler(store, &fakeChat{status: status},
		directory.NewRecorder(store, quiet()), nil, quiet())

	r.Run(context.Background())

	store.mu.Lock()
	deletes := len(store.deletes)
	store.mu.Unlock()
	if deletes != 0 {
		t.Fatalf("выполнено %d удалений до срабатывания предохранителя", deletes)
	}
}
