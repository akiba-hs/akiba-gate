package auth_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/testsupport"
)

func newVerifier(t *testing.T) (*auth.Verifier, testsupport.KeyPair) {
	t.Helper()
	kp := testsupport.NewKeyPair(t)
	v, err := auth.NewVerifier(kp.PublicPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v, kp
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	v, kp := newVerifier(t)

	claims, err := v.Verify(kp.ResidentToken(t))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.TelegramID != "42424242" {
		t.Fatalf("TelegramID = %q", claims.TelegramID)
	}
	if !claims.IsResident {
		t.Fatal("ожидался признак резидента")
	}
	if got := claims.UID(); got != "tg42424242" {
		t.Fatalf("UID = %q, ожидалось tg42424242", got)
	}
	if got := claims.DisplayName(); got != "Alice Example" {
		t.Fatalf("DisplayName = %q", got)
	}
}

func TestVerifyRejectsEmptyToken(t *testing.T) {
	v, _ := newVerifier(t)
	if _, err := v.Verify(""); err != auth.ErrNoToken {
		t.Fatalf("ожидалась ErrNoToken, получено %v", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	v, kp := newVerifier(t)
	token := kp.Token(t, testsupport.TokenOptions{IsResident: true, ExpiresIn: -time.Minute})

	if _, err := v.Verify(token); err == nil {
		t.Fatal("просроченный токен принят")
	}
}

func TestVerifyRejectsTokenFromAnotherKey(t *testing.T) {
	v, _ := newVerifier(t)
	other := testsupport.NewKeyPair(t)

	if _, err := v.Verify(other.ResidentToken(t)); err == nil {
		t.Fatal("токен, подписанный чужим ключом, принят")
	}
}

// Ключевая проверка безопасности: публичный ключ не должен приниматься как
// секрет HMAC. Иначе подделать токен может любой, кто знает открытый ключ.
func TestVerifyRejectsHS256Forgery(t *testing.T) {
	v, kp := newVerifier(t)

	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":          "1",
		"is_resident": true,
		"exp":         time.Now().Add(time.Hour).Unix(),
	}).SignedString(kp.PublicPEM)
	if err != nil {
		t.Fatalf("подпись подделки: %v", err)
	}
	if _, err := v.Verify(forged); err == nil {
		t.Fatal("токен HS256, подписанный публичным ключом, принят")
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	v, _ := newVerifier(t)
	token, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"id": "1", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("подпись alg=none: %v", err)
	}
	if _, err := v.Verify(token); err == nil {
		t.Fatal("токен с alg=none принят")
	}
}

func TestVerifyRequiresExpiration(t *testing.T) {
	v, kp := newVerifier(t)
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"id": "1", "is_resident": true,
	}).SignedString(kp.Private)
	if err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if _, err := v.Verify(token); err == nil {
		t.Fatal("токен без exp принят")
	}
}

func TestVerifyRejectsTokenWithoutID(t *testing.T) {
	v, kp := newVerifier(t)
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"is_resident": true, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(kp.Private)
	if err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if _, err := v.Verify(token); err == nil {
		t.Fatal("токен без id принят")
	}
}

func TestNewVerifierRejectsGarbage(t *testing.T) {
	if _, err := auth.NewVerifier([]byte("не ключ")); err == nil {
		t.Fatal("мусор вместо ключа принят")
	}
}

func TestDisplayNameFallbacks(t *testing.T) {
	cases := []struct {
		name   string
		claims auth.Claims
		want   string
	}{
		{"имя и фамилия", auth.Claims{FirstName: "Ann", LastName: "Lee"}, "Ann Lee"},
		{"только имя", auth.Claims{FirstName: "Ann"}, "Ann"},
		{"только username", auth.Claims{Username: "ann"}, "@ann"},
		{"ничего", auth.Claims{TelegramID: "7"}, "tg7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.claims.DisplayName(); got != tc.want {
				t.Fatalf("получено %q, ожидалось %q", got, tc.want)
			}
		})
	}
}

// id в токене — основа имени аккаунта в Nextcloud, пути в OCS и метки AAD.
// auth-service приводит его к числу перед подписью; проверка здесь нужна на
// случай второго эмитента — по той же логике, по какой проверяется photo_url.
func TestVerifyRejectsNonNumericTelegramID(t *testing.T) {
	kp := testsupport.NewKeyPair(t)
	v, err := auth.NewVerifier(kp.PublicPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	token := kp.Token(t, testsupport.TokenOptions{TelegramID: "../admin", IsResident: true})

	if _, err := v.Verify(token); err == nil {
		t.Fatal("принят токен с нечисловым id")
	}
}
