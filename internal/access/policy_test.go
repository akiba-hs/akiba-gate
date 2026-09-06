package access_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

// memoryGrants — выданные права без базы.
type memoryGrants struct {
	byUser map[string][]string
	err    error
}

func (g memoryGrants) ResidentServices(_ context.Context, id string) ([]string, error) {
	if g.err != nil {
		return nil, g.err
	}
	return g.byUser[id], nil
}

// residentID — резидент с заданным Telegram-ID. Отдельно от resident() из
// соседнего файла: там он безымянный, а здесь личность и есть предмет теста.
func residentID(id string) *auth.Claims {
	return &auth.Claims{TelegramID: id, Username: "u" + id, IsResident: true}
}

// quietLog глушит журнал: Require пишет в него отказы, и в выводе тестов они
// были бы шумом.
type quietLog struct{}

func (quietLog) Warn(string, ...any) {}

// Главное умолчание: новому резиденту не доступно ничего, пока администратор
// не откроет. Обратное означало бы, что любой попавший в чат человек получает
// доступ ко всему на то время, пока его не заметят.
func TestStorePolicyDeniesByDefault(t *testing.T) {
	p := access.StorePolicy{Grants: memoryGrants{}, RootAdmin: "1"}

	got, err := p.AllowedFor(context.Background(), residentID("42"))
	if err != nil {
		t.Fatalf("AllowedFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("новому резиденту выдано %v", got)
	}
}

func TestStorePolicyReturnsGrantedServices(t *testing.T) {
	p := access.StorePolicy{
		Grants:    memoryGrants{byUser: map[string][]string{"42": {"jellyfin", "nextcloud"}}},
		RootAdmin: "1",
	}

	got, err := p.AllowedFor(context.Background(), residentID("42"))
	if err != nil {
		t.Fatalf("AllowedFor: %v", err)
	}
	if !slices.Contains(got, access.Jellyfin) || !slices.Contains(got, access.Nextcloud) {
		t.Fatalf("выдано %v", got)
	}
	if slices.Contains(got, access.QBittorrent) {
		t.Fatalf("выдан лишний сервис: %v", got)
	}
}

// Администратору из конфигурации доступно всё и мимо базы: иначе одна неверная
// галочка заперла бы систему на себе.
func TestStorePolicyGivesRootEverything(t *testing.T) {
	p := access.StorePolicy{Grants: memoryGrants{}, RootAdmin: "1"}

	got, err := p.AllowedFor(context.Background(), residentID("1"))
	if err != nil {
		t.Fatalf("AllowedFor: %v", err)
	}
	if !slices.Equal(got, access.All()) {
		t.Fatalf("администратору выдано %v, ожидалось всё", got)
	}
}

// Доступ администратора не должен зависеть даже от исправности базы: сбой
// SQLite не может лишить единственного человека права раздавать доступ.
func TestStorePolicyGivesRootEverythingDespiteStoreFailure(t *testing.T) {
	p := access.StorePolicy{
		Grants:    memoryGrants{err: errors.New("база недоступна")},
		RootAdmin: "1",
	}

	got, err := p.AllowedFor(context.Background(), residentID("1"))
	if err != nil {
		t.Fatalf("AllowedFor: %v", err)
	}
	if len(got) != len(access.All()) {
		t.Fatalf("администратору выдано %v", got)
	}
}

// Не резидент не получает ничего, даже если права ему когда-то выдавали:
// человек выбыл из чата, и старая строка в базе не должна его пускать.
func TestStorePolicyDeniesNonResidentWithGrants(t *testing.T) {
	p := access.StorePolicy{
		Grants:    memoryGrants{byUser: map[string][]string{"42": {"jellyfin"}}},
		RootAdmin: "1",
	}
	former := &auth.Claims{TelegramID: "42", IsResident: false}

	got, err := p.AllowedFor(context.Background(), former)
	if err != nil {
		t.Fatalf("AllowedFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("выбывшему резиденту выдано %v", got)
	}
}

func TestStorePolicyDeniesAnonymous(t *testing.T) {
	p := access.StorePolicy{Grants: memoryGrants{}, RootAdmin: "1"}
	got, err := p.AllowedFor(context.Background(), nil)
	if err != nil {
		t.Fatalf("AllowedFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("анониму выдано %v", got)
	}
}

// Сбой базы — это ошибка, а не пустой список: Require обязан отличить «прав
// нет» от «выяснить не удалось», иначе сбой SQLite выглядел бы как штатный
// запрет, и никто бы его не заметил.
func TestStorePolicyReportsStoreFailure(t *testing.T) {
	p := access.StorePolicy{
		Grants:    memoryGrants{err: errors.New("база недоступна")},
		RootAdmin: "1",
	}
	if _, err := p.AllowedFor(context.Background(), residentID("42")); err == nil {
		t.Fatal("сбой базы выдан за отсутствие прав")
	}
}

// В базе может остаться право на сервис, который убрали из кода.
func TestStorePolicyIgnoresUnknownServices(t *testing.T) {
	p := access.StorePolicy{
		Grants:    memoryGrants{byUser: map[string][]string{"42": {"jellyfin", "пылесос"}}},
		RootAdmin: "1",
	}

	got, _ := p.AllowedFor(context.Background(), residentID("42"))
	if !slices.Equal(got, []access.ID{access.Jellyfin}) {
		t.Fatalf("выдано %v", got)
	}
}

// Админка всегда последняя в списке: это инструмент, а не сервис для жизни.
func TestAdminIsLastService(t *testing.T) {
	all := access.All()
	if all[len(all)-1] != access.Admin {
		t.Fatalf("порядок сервисов: %v", all)
	}
}

func TestKnownRejectsForeignServices(t *testing.T) {
	for _, id := range access.All() {
		if !access.Known(id) {
			t.Fatalf("свой сервис %q не признан", id)
		}
	}
	for _, id := range []access.ID{"", "пылесос", "ADMIN", "jellyfin "} {
		if access.Known(id) {
			t.Fatalf("чужой идентификатор %q признан своим", id)
		}
	}
}

// Require — тот слой, который делает доступ настоящим, а не косметическим:
// адрес сервиса можно набрать руками, минуя портал.
func TestRequireBlocksServiceWithoutGrant(t *testing.T) {
	p := access.StorePolicy{
		Grants:    memoryGrants{byUser: map[string][]string{"42": {"jellyfin"}}},
		RootAdmin: "1",
	}
	reached := false
	h := access.Require(p, access.QBittorrent, quietLog{},
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	r := httptest.NewRequest(http.MethodGet, "/qbittorrent/", nil)
	r = r.WithContext(auth.WithClaims(r.Context(), residentID("42")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("код ответа %d, ожидался 403", w.Code)
	}
	if reached {
		t.Fatal("запрос дошёл до сервиса, на который нет права")
	}
}

func TestRequireAllowsGrantedService(t *testing.T) {
	p := access.StorePolicy{
		Grants:    memoryGrants{byUser: map[string][]string{"42": {"jellyfin"}}},
		RootAdmin: "1",
	}
	reached := false
	h := access.Require(p, access.Jellyfin, quietLog{},
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	r := httptest.NewRequest(http.MethodGet, "/jellyfin/", nil)
	r = r.WithContext(auth.WithClaims(r.Context(), residentID("42")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !reached {
		t.Fatalf("выданный сервис недоступен, код ответа %d", w.Code)
	}
}

// Снятая галочка обязана закрывать доступ немедленно, без перезапуска шлюза:
// политика ходит в базу на каждый запрос, кэша между ними нет.
func TestRequireReactsToRevokedGrant(t *testing.T) {
	grants := &mutableGrants{byUser: map[string][]string{"42": {"jellyfin"}}}
	p := access.StorePolicy{Grants: grants, RootAdmin: "1"}
	h := access.Require(p, access.Jellyfin, quietLog{},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	call := func() int {
		r := httptest.NewRequest(http.MethodGet, "/jellyfin/", nil)
		r = r.WithContext(auth.WithClaims(r.Context(), residentID("42")))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := call(); code != http.StatusOK {
		t.Fatalf("до отзыва код %d, ожидался 200", code)
	}
	grants.byUser["42"] = nil // администратор снял галочку
	if code := call(); code != http.StatusForbidden {
		t.Fatalf("после отзыва код %d, ожидался 403", code)
	}
}

// Сбой базы закрывает доступ, а не открывает: иначе недоступность SQLite
// превращалась бы в дыру.
func TestRequireClosesOnStoreFailure(t *testing.T) {
	p := access.StorePolicy{Grants: memoryGrants{err: errors.New("база недоступна")}, RootAdmin: "1"}
	reached := false
	h := access.Require(p, access.Jellyfin, quietLog{},
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	r := httptest.NewRequest(http.MethodGet, "/jellyfin/", nil)
	r = r.WithContext(auth.WithClaims(r.Context(), residentID("42")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if reached {
		t.Fatal("при сбое базы запрос прошёл к сервису")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("код ответа %d, ожидался 503", w.Code)
	}
}

// mutableGrants позволяет менять права между запросами.
type mutableGrants struct{ byUser map[string][]string }

func (g *mutableGrants) ResidentServices(_ context.Context, id string) ([]string, error) {
	return g.byUser[id], nil
}

// Каждый известный сервис обязан иметь карточку: без неё он выдан, но не
// показан — доступ есть, а зайти неоткуда.
func TestCatalogDescribesEveryService(t *testing.T) {
	cat := access.Catalog{
		JellyfinURL:  "/sso/jellyfin",
		QbitURL:      "/qbittorrent/",
		NextcloudURL: "/nextcloud",
		AdminURL:     "/admin",
	}
	m := testsupport.Messages()

	for _, id := range access.All() {
		svc, ok := cat.Describe(id, m)
		if !ok {
			t.Errorf("нет карточки для %q", id)
			continue
		}
		if svc.Title == "" || svc.URL == "" {
			t.Errorf("карточка %q неполная: %+v", id, svc)
		}
		if svc.ID != id {
			t.Errorf("карточка %q содержит идентификатор %q", id, svc.ID)
		}
	}
	if _, ok := cat.Describe("пылесос", m); ok {
		t.Error("нашлась карточка для несуществующего сервиса")
	}
}
