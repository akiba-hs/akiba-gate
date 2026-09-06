package access_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

func resident() *auth.Claims {
	return &auth.Claims{TelegramID: "42", Username: "alice", IsResident: true}
}

func stranger() *auth.Claims {
	return &auth.Claims{TelegramID: "43", Username: "bob", IsResident: false}
}

var catalog = access.Catalog{
	JellyfinURL:  "/sso/jellyfin",
	QbitURL:      "/qbittorrent/",
	NextcloudURL: "/nextcloud",
}

func TestResidentPolicyGivesListedServices(t *testing.T) {
	p := access.ResidentPolicy{Services: []access.ID{access.Jellyfin}}
	got, _ := p.AllowedFor(context.Background(), resident())
	if len(got) != 1 || got[0] != access.Jellyfin {
		t.Fatalf("доступно %v, ожидался только Jellyfin", got)
	}
}

func TestResidentPolicyDeniesNonResidentAndAnonymous(t *testing.T) {
	p := access.ResidentPolicy{Services: access.All()}
	if got, _ := p.AllowedFor(context.Background(), stranger()); len(got) != 0 {
		t.Errorf("не резиденту доступно %v", got)
	}
	if got, _ := p.AllowedFor(context.Background(), nil); len(got) != 0 {
		t.Errorf("анониму доступно %v", got)
	}
}

// Список политики — копия: вызывающий код не должен уметь расширить себе
// доступ, дописав в возвращённый срез.
func TestResidentPolicyReturnsCopy(t *testing.T) {
	services := []access.ID{access.Jellyfin}
	p := access.ResidentPolicy{Services: services}
	got, _ := p.AllowedFor(context.Background(), resident())
	got[0] = access.Nextcloud

	if again, _ := p.AllowedFor(context.Background(), resident()); again[0] != access.Jellyfin {
		t.Fatalf("политика изменилась снаружи: %v", again)
	}
}

func TestServicesForKeepsCatalogOrder(t *testing.T) {
	p := access.ResidentPolicy{Services: []access.ID{access.Nextcloud, access.Jellyfin}}
	got, _ := access.ServicesFor(context.Background(), p, catalog, testsupport.Messages(), resident())

	if len(got) != 2 {
		t.Fatalf("карточек %d, ожидалось 2", len(got))
	}
	if got[0].ID != access.Jellyfin || got[1].ID != access.Nextcloud {
		t.Fatalf("порядок = %v, ожидался порядок из All()", []access.ID{got[0].ID, got[1].ID})
	}
	if got[0].Title != testsupport.Messages().ServiceJellyfin {
		t.Errorf("название взято не из переводов: %q", got[0].Title)
	}
}

func TestServicesForReturnsNothingWithoutAccess(t *testing.T) {
	p := access.ResidentPolicy{Services: access.All()}
	if got, _ := access.ServicesFor(context.Background(), p, catalog, testsupport.Messages(), stranger()); got != nil {
		t.Fatalf("не резиденту собраны карточки: %v", got)
	}
}

// Скрыть карточку недостаточно: адрес сервиса легко набрать руками.
func TestRequireBlocksForbiddenService(t *testing.T) {
	p := access.ResidentPolicy{Services: []access.ID{access.Jellyfin}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var reached bool
	h := access.Require(p, access.QBittorrent, log,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	r := httptest.NewRequest(http.MethodGet, "/qbittorrent/", nil)
	r = r.WithContext(auth.WithClaims(r.Context(), resident()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("код %d, ожидался 403", w.Code)
	}
	if reached {
		t.Fatal("запрос дошёл до закрытого сервиса")
	}
}

func TestRequirePassesAllowedService(t *testing.T) {
	p := access.ResidentPolicy{Services: []access.ID{access.QBittorrent}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := access.Require(p, access.QBittorrent, log,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ок")) }))

	r := httptest.NewRequest(http.MethodGet, "/qbittorrent/", nil)
	r = r.WithContext(auth.WithClaims(r.Context(), resident()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Body.String() != "ок" {
		t.Fatalf("тело %q, разрешённый сервис должен открываться", w.Body.String())
	}
}

// Запрос без опознанного резидента тоже не должен проходить: Guard мог бы
// однажды оказаться не на месте.
func TestRequireBlocksAnonymous(t *testing.T) {
	p := access.ResidentPolicy{Services: access.All()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := access.Require(p, access.Jellyfin, log,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("аноним прошёл") }))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sso/jellyfin", nil))

	if w.Code != http.StatusForbidden {
		t.Fatalf("код %d, ожидался 403", w.Code)
	}
}

// failingPolicy изображает будущую реализацию с базой, у которой отказал запрос.
type failingPolicy struct{}

func (failingPolicy) AllowedFor(context.Context, *auth.Claims) ([]access.ID, error) {
	return nil, errors.New("база недоступна")
}

// Не смогли выяснить права — закрываем. Открыть «на всякий случай» значило бы
// превратить сбой базы в дыру, и заметить это было бы нечем.
func TestRequireDeniesWhenPolicyFails(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := access.Require(failingPolicy{}, access.Jellyfin, log,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("запрос прошёл при сбое политики")
		}))

	r := httptest.NewRequest(http.MethodGet, "/sso/jellyfin", nil)
	r = r.WithContext(auth.WithClaims(r.Context(), resident()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("код %d, ожидался 503", w.Code)
	}
}

// Ошибка обязана доходить до вызывающего, а не превращаться в пустой список:
// пустой портал выглядит ровно как «у тебя нет доступа».
func TestServicesForPropagatesError(t *testing.T) {
	_, err := access.ServicesFor(context.Background(), failingPolicy{}, catalog,
		testsupport.Messages(), resident())
	if err == nil {
		t.Fatal("сбой политики выдан за отсутствие сервисов")
	}
}
