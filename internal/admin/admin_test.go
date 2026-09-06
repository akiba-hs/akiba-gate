package admin_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/admin"
	"github.com/akiba-hs/akiba-gate/internal/audit"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

const rootID = "270369579"

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// memoryStore — резиденты без базы.
type memoryStore struct {
	mu        sync.Mutex
	residents []audit.Resident
	err       error
	// saved запоминает последний вызов SetResidentServices.
	saved map[string][]string
}

func (m *memoryStore) Residents(context.Context) ([]audit.Resident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	return append([]audit.Resident(nil), m.residents...), nil
}

func (m *memoryStore) SetResidentServices(_ context.Context, id string, services []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if m.saved == nil {
		m.saved = map[string][]string{}
	}
	m.saved[id] = append([]string(nil), services...)
	for i := range m.residents {
		if m.residents[i].TelegramID == id {
			m.residents[i].Services = append([]string(nil), services...)
		}
	}
	return nil
}

// spyReconciler запоминает, что сверку дёрнули.
type spyReconciler struct {
	mu       sync.Mutex
	triggers int
}

func (s *spyReconciler) Trigger(context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.triggers++
	return true
}

func (s *spyReconciler) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.triggers
}

func newHandler(store *memoryStore, rec admin.Reconciler) *admin.Handler {
	return &admin.Handler{
		Store: store,
		Texts: testsupport.StaticTexts{},
		Catalog: access.Catalog{
			JellyfinURL:  "/sso/jellyfin",
			QbitURL:      "/qbittorrent/",
			NextcloudURL: "/nextcloud",
			AdminURL:     admin.Path,
		},
		RootAdmin: rootID,
		Reconcile: rec,
		Log:       quiet(),
	}
}

func people() *memoryStore {
	return &memoryStore{residents: []audit.Resident{
		{TelegramID: "1", Username: "alice", FirstName: "Алиса", LastName: "Иванова",
			Services: []string{"jellyfin", "qbittorrent"}},
		{TelegramID: "2", Username: "bob", FirstName: "Борис", LastName: "Петров"},
		{TelegramID: "3", Username: "clara", FirstName: "Клара", LastName: "Сидорова",
			Services: []string{"nextcloud", "admin"}},
		{TelegramID: rootID, Username: "ilvesbogdan", FirstName: "Bogdan", LastName: "Ilves"},
	}}
}

// asAdmin подставляет личность администратора — так же, как это делает Guard.
func asAdmin(r *http.Request) *http.Request {
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{
		TelegramID: rootID, Username: "ilvesbogdan", IsResident: true,
	}))
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, asAdmin(httptest.NewRequest(http.MethodGet, target, nil)))
	return w
}

func TestListShowsResidentsWithServices(t *testing.T) {
	w := get(t, newHandler(people(), nil), admin.Path)

	if w.Code != http.StatusOK {
		t.Fatalf("код ответа %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Алиса Иванова", "@alice", "Борис Петров", "@bob"} {
		if !strings.Contains(body, want) {
			t.Errorf("в списке нет %q", want)
		}
	}
	// Справа от Алисы — названия её сервисов через запятую.
	if !strings.Contains(body, "Jellyfin") || !strings.Contains(body, "qBittorrent") {
		t.Error("не показаны выданные сервисы")
	}
	// У Бориса прав нет — это должно быть видно, а не выглядеть пустотой.
	if !strings.Contains(body, "нет доступа") {
		t.Error("отсутствие прав никак не обозначено")
	}
}

// Карточка администратора не нажимается и не показывает список сервисов: ему
// доступно всё всегда, и перечисление создавало бы впечатление, что этот
// набор кто-то ему выдал и может отобрать.
func TestRootCardIsNotClickable(t *testing.T) {
	w := get(t, newHandler(people(), nil), admin.Path)
	body := w.Body.String()

	if strings.Contains(body, `href="/admin?user=`+rootID+`"`) {
		t.Fatal("карточка администратора нажимается")
	}
	// А обычные — нажимаются.
	if !strings.Contains(body, `href="/admin?user=1"`) {
		t.Fatal("карточка обычного резидента не нажимается")
	}
	if !strings.Contains(body, "администратор из конфигурации") {
		t.Error("администратор ничем не помечен")
	}
}

// Запрет на нажатие должен быть настоящим, а не оформительским: прямая ссылка
// на карточку администратора тоже не должна открывать галочки.
func TestRootCannotBeOpenedByDirectLink(t *testing.T) {
	w := get(t, newHandler(people(), nil), admin.Path+"?user="+rootID)

	body := w.Body.String()
	if strings.Contains(body, `type="checkbox"`) {
		t.Fatal("галочки администратора открылись по прямой ссылке")
	}
	if !strings.Contains(body, "менять нельзя") {
		t.Errorf("нет объяснения отказа: %s", body)
	}
}

func TestEditorShowsCheckboxes(t *testing.T) {
	w := get(t, newHandler(people(), nil), admin.Path+"?user=1")

	body := w.Body.String()
	// Все известные сервисы должны быть в форме, включая саму админку:
	// через неё и назначается второй администратор.
	for _, id := range access.All() {
		if !strings.Contains(body, `value="`+string(id)+`"`) {
			t.Errorf("в форме нет сервиса %q", id)
		}
	}
	// Выданные отмечены, невыданные — нет.
	if !strings.Contains(body, `value="jellyfin" checked`) {
		t.Error("выданный jellyfin не отмечен")
	}
	if strings.Contains(body, `value="nextcloud" checked`) {
		t.Error("невыданный nextcloud отмечен")
	}
}

func TestUnknownResidentReportsError(t *testing.T) {
	w := get(t, newHandler(people(), nil), admin.Path+"?user=404")

	if !strings.Contains(w.Body.String(), "нет в списке") {
		t.Fatalf("нет сообщения о неизвестном резиденте: %s", w.Body.String())
	}
}

func post(t *testing.T, h http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, admin.Path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, asAdmin(r))
	return w
}

func TestSaveGrantsServices(t *testing.T) {
	store := people()
	w := post(t, newHandler(store, nil), url.Values{
		"user":    {"2"},
		"service": {"jellyfin", "nextcloud"},
	})

	if w.Code != http.StatusSeeOther {
		t.Fatalf("код ответа %d, ожидался 303", w.Code)
	}
	got := store.saved["2"]
	if !slices.Equal(got, []string{"jellyfin", "nextcloud"}) {
		t.Fatalf("сохранено %v", got)
	}
}

// Пустая форма означает «снять всё», а не «ничего не менять»: иначе снятие
// последней галочки было бы невозможно.
func TestSaveWithNoCheckboxesRevokesEverything(t *testing.T) {
	store := people()
	w := post(t, newHandler(store, nil), url.Values{"user": {"1"}})

	if w.Code != http.StatusSeeOther {
		t.Fatalf("код ответа %d", w.Code)
	}
	if got, ok := store.saved["1"]; !ok || len(got) != 0 {
		t.Fatalf("сохранено %v (записано: %t)", got, ok)
	}
}

// Через админку назначается второй администратор — ради этого сервис Admin и
// показывается в галочках наравне с остальными.
func TestSaveCanGrantAdmin(t *testing.T) {
	store := people()
	post(t, newHandler(store, nil), url.Values{
		"user":    {"1"},
		"service": {string(access.Admin)},
	})

	if !slices.Contains(store.saved["1"], string(access.Admin)) {
		t.Fatalf("права администратора не выданы: %v", store.saved["1"])
	}
}

// Права администратора из конфигурации не меняет никто, включая второго
// администратора: иначе первого можно было бы запереть снаружи его же системы.
func TestSaveRefusesToTouchRoot(t *testing.T) {
	store := people()
	w := post(t, newHandler(store, nil), url.Values{
		"user":    {rootID},
		"service": {"jellyfin"},
	})

	if w.Code != http.StatusForbidden {
		t.Fatalf("код ответа %d, ожидался 403", w.Code)
	}
	if _, touched := store.saved[rootID]; touched {
		t.Fatal("права администратора из конфигурации записаны в базу")
	}
}

// В форму можно дописать что угодно: без фильтра эта строка уехала бы в базу.
func TestSaveIgnoresUnknownServices(t *testing.T) {
	store := people()
	post(t, newHandler(store, nil), url.Values{
		"user":    {"2"},
		"service": {"jellyfin", "пылесос", "../../etc/passwd"},
	})

	if !slices.Equal(store.saved["2"], []string{"jellyfin"}) {
		t.Fatalf("сохранено %v", store.saved["2"])
	}
}

func TestSaveRequiresUser(t *testing.T) {
	w := post(t, newHandler(people(), nil), url.Values{"service": {"jellyfin"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("код ответа %d, ожидался 400", w.Code)
	}
}

// Сверка состава чата запускается открытием списка и не должна его задерживать.
func TestListTriggersReconcile(t *testing.T) {
	spy := &spyReconciler{}
	get(t, newHandler(people(), spy), admin.Path)

	if spy.count() != 1 {
		t.Fatalf("сверка запущена %d раз", spy.count())
	}
}

// Сохранение — не повод сверяться с Telegram: это отдельное действие, и лишний
// обход всех резидентов на каждое нажатие «Сохранить» ни к чему.
func TestSaveDoesNotTriggerReconcile(t *testing.T) {
	spy := &spyReconciler{}
	post(t, newHandler(people(), spy), url.Values{"user": {"2"}, "service": {"jellyfin"}})

	if spy.count() != 0 {
		t.Fatalf("сохранение запустило сверку %d раз", spy.count())
	}
}

func TestListSurvivesStoreFailure(t *testing.T) {
	store := &memoryStore{err: errAny{}}
	w := get(t, newHandler(store, nil), admin.Path)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("код ответа %d, ожидался 500", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Не удалось прочитать") {
		t.Errorf("нет объяснения ошибки: %s", w.Body.String())
	}
}

func TestEmptyListExplainsItself(t *testing.T) {
	w := get(t, newHandler(&memoryStore{}, nil), admin.Path)

	if !strings.Contains(w.Body.String(), "Пока никто не заходил") {
		t.Fatalf("пустой список ничего не объясняет: %s", w.Body.String())
	}
}

// Страница персональная и показывает, кому что доступно: общий кэш её
// сохранять не должен.
func TestPageIsNotCached(t *testing.T) {
	w := get(t, newHandler(people(), nil), admin.Path)
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestRejectsOtherMethods(t *testing.T) {
	h := newHandler(people(), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, asAdmin(httptest.NewRequest(http.MethodDelete, admin.Path, nil)))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("код ответа %d, ожидался 405", w.Code)
	}
}

// Имена приходят из Telegram и могут содержать разметку.
func TestNamesAreEscaped(t *testing.T) {
	store := &memoryStore{residents: []audit.Resident{
		{TelegramID: "9", Username: "x", FirstName: `<script>alert(1)</script>`},
	}}
	w := get(t, newHandler(store, nil), admin.Path)

	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("разметка из имени попала на страницу как есть")
	}
}

type errAny struct{}

func (errAny) Error() string { return "база недоступна" }

// postFrom отправляет форму, притворяясь запросом с указанного источника.
func postFrom(t *testing.T, h http.Handler, origin, fetchSite string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://inside.akiba.space"+admin.Path,
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if fetchSite != "" {
		r.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, asAdmin(r))
	return w
}

func withHosts(store *memoryStore) *admin.Handler {
	h := newHandler(store, nil)
	base, _ := url.Parse("https://inside.akiba.space")
	h.Hosts = auth.HostPolicy{Base: base}
	return h
}

// Это самый привилегированный POST в системе: им раздаются права, включая
// права администратора. Куку ставит внешний auth-service, её атрибуты нам не
// подчиняются, поэтому происхождение проверяем сами.
func TestSaveRejectsCrossSiteRequests(t *testing.T) {
	cases := []struct{ name, origin, fetchSite string }{
		{"чужой Origin", "https://evil.example", ""},
		{"Sec-Fetch-Site: cross-site", "", "cross-site"},
		{"Sec-Fetch-Site: same-site", "", "same-site"},
		{"чужой поддомен", "https://evil.akiba.space", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := people()
			w := postFrom(t, withHosts(store), c.origin, c.fetchSite,
				url.Values{"user": {"2"}, "service": {string(access.Admin)}})

			if w.Code != http.StatusForbidden {
				t.Fatalf("код ответа %d, ожидался 403", w.Code)
			}
			if _, touched := store.saved["2"]; touched {
				t.Fatal("права изменены запросом с чужой страницы")
			}
		})
	}
}

// Своя же форма обязана работать: защита не должна ломать админку.
func TestSaveAcceptsOwnOrigin(t *testing.T) {
	for _, c := range []struct{ name, origin, fetchSite string }{
		{"свой Origin", "https://inside.akiba.space", ""},
		{"same-origin", "https://inside.akiba.space", "same-origin"},
		{"без метаданных", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := people()
			w := postFrom(t, withHosts(store), c.origin, c.fetchSite,
				url.Values{"user": {"2"}, "service": {"jellyfin"}})

			if w.Code != http.StatusSeeOther {
				t.Fatalf("код ответа %d, ожидался 303", w.Code)
			}
		})
	}
}

// Опечатка в идентификаторе — ошибка запроса, а не сбой сервиса: 500 поднял бы
// оператора среди ночи на промах мимо кнопки.
func TestSaveReportsUnknownResidentAsNotFound(t *testing.T) {
	store := &memoryStore{err: audit.ErrNoResident}
	w := post(t, newHandler(store, nil), url.Values{"user": {"404"}, "service": {"jellyfin"}})

	if w.Code != http.StatusNotFound {
		t.Fatalf("код ответа %d, ожидался 404", w.Code)
	}
}

// Цвет плашки — единственное, что отличает сервисы в списке с одного взгляда.
// Совпавшие классы означали бы два сервиса одного цвета, и разница пропала бы.
func TestEveryServiceGetsItsOwnTag(t *testing.T) {
	w := get(t, newHandler(people(), nil), admin.Path)
	body := w.Body.String()

	// Каждый известный сервис выдан кому-то из people(), значит на странице
	// обязаны быть все четыре класса — и все разные.
	classes := map[string]bool{}
	for _, want := range []string{"tag-jellyfin", "tag-qbit", "tag-nextcloud", "tag-admin"} {
		if !strings.Contains(body, `class="tag `+want+`"`) {
			t.Errorf("на странице нет плашки %q", want)
		}
		classes[want] = true
	}
	if len(classes) != len(access.All()) {
		t.Fatalf("классов %d на %d сервисов", len(classes), len(access.All()))
	}
	// Запасной класс появляться не должен: все известные сервисы разобраны.
	if strings.Contains(body, `class="tag tag-other"`) {
		t.Error("сервис остался без своего цвета")
	}
}

// Права администратора выделены отдельным классом — тем, на который в таблице
// стилей навешаны крупный жирный шрифт и цвет акцента.
func TestAdminTagIsDistinct(t *testing.T) {
	store := &memoryStore{residents: []audit.Resident{
		{TelegramID: "7", Username: "clara", FirstName: "Клара",
			Services: []string{string(access.Admin)}},
	}}
	body := get(t, newHandler(store, nil), admin.Path).Body.String()

	if !strings.Contains(body, `class="tag tag-admin"`) {
		t.Fatalf("плашка администратора без своего класса: %s", body)
	}
	// Ищем именно атрибут: сами классы объявлены в таблице стилей страницы,
	// и поиск по голому имени нашёл бы их там.
	for _, other := range []string{"tag-jellyfin", "tag-qbit", "tag-nextcloud"} {
		if strings.Contains(body, `class="tag `+other+`"`) {
			t.Errorf("на плашку администратора попал класс %q", other)
		}
	}
}
