// Пакет auth проверяет JWT, который выдаёт внешний auth-service
// (github.com/akiba-hs/auth-service), и превращает его в удобную структуру.
//
// Важное свойство: шлюз никогда не выпускает токены сам и не знает приватного
// ключа. У него есть только публичный ключ — этого достаточно для проверки
// подписи и невозможно для подделки.
package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Ошибки уровня политики доступа (в отличие от ошибок разбора токена).
var (
	// ErrNoToken — куки с токеном нет вовсе.
	ErrNoToken = errors.New("auth: токен отсутствует")
	// ErrInvalidToken — токен есть, но не проходит проверку подписи или срока.
	ErrInvalidToken = errors.New("auth: токен недействителен")
	// ErrNotResident — токен валиден, но человек не состоит в чате резидентов.
	ErrNotResident = errors.New("auth: человек не резидент")
)

// Claims — полезная нагрузка токена auth-service.
//
// Внимание: auth-service кладёт в токен параметры Telegram-виджета «как есть»,
// то есть строками. Поэтому id — строка, а не число.
type Claims struct {
	TelegramID string `json:"id"`
	Username   string `json:"username"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	PhotoURL   string `json:"photo_url"`
	IsResident bool   `json:"is_resident"`

	jwt.RegisteredClaims
}

// UID — стабильный идентификатор резидента для внешних сервисов.
//
// Берём именно Telegram ID, а не @username: username резидент может
// сменить в любой момент, и тогда он «потеряет» свой аккаунт в Nextcloud.
func (c *Claims) UID() string {
	return "tg" + c.TelegramID
}

// DisplayName — человекочитаемое имя для отображения и для Nextcloud.
// Если имени нет, откатываемся на @username, затем на UID.
func (c *Claims) DisplayName() string {
	name := strings.TrimSpace(c.FirstName + " " + c.LastName)
	if name != "" {
		return name
	}
	if c.Username != "" {
		return "@" + c.Username
	}
	return c.UID()
}

// Verifier проверяет подпись токенов одним публичным ключом.
type Verifier struct {
	key    *rsa.PublicKey
	parser *jwt.Parser
}

// NewVerifier разбирает публичный ключ RSA в формате PEM.
//
// Принимаются оба обычных представления: SubjectPublicKeyInfo ("BEGIN PUBLIC
// KEY", вывод `openssl rsa -pubout`) и PKCS#1 ("BEGIN RSA PUBLIC KEY").
func NewVerifier(pemBytes []byte) (*Verifier, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("auth: не удалось разобрать публичный ключ: %w", err)
	}
	return &Verifier{
		key: key,
		// Алгоритм фиксируем жёстко: иначе возможна подмена на HS256,
		// где публичный ключ становится общим секретом.
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			jwt.WithExpirationRequired(),
		),
	}, nil
}

// Verify проверяет подпись и срок действия токена.
func (v *Verifier) Verify(token string) (*Claims, error) {
	if token == "" {
		return nil, ErrNoToken
	}
	claims := &Claims{}
	if _, err := v.parser.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
		return v.key, nil
	}); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidToken, err)
	}
	if claims.TelegramID == "" {
		return nil, fmt.Errorf("%w: в токене нет поля id", ErrInvalidToken)
	}
	// Telegram-ID обязан быть числом: из него собирается имя аккаунта в
	// Nextcloud, путь в OCS и метка AAD при шифровании пароля. auth-service
	// приводит его к int перед подписью, так что сегодня это вторая линия —
	// на случай, если эмитентов когда-нибудь станет двое.
	if !isDigits(claims.TelegramID) {
		return nil, fmt.Errorf("%w: поле id не является числом", ErrInvalidToken)
	}
	return claims, nil
}

// isDigits сообщает, состоит ли строка только из цифр и непуста.
func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
