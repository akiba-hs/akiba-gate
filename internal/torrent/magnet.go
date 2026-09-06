package torrent

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrNoInfoHash — в magnet-ссылке нет пригодного xt=urn:btih:.
var ErrNoInfoHash = errors.New("torrent: в magnet-ссылке нет infohash")

// ParseMagnet достаёт infohash (в нижнем регистре, hex) и имя из magnet-ссылки.
//
// Поддерживаются оба исторических представления btih: 40 символов hex и
// 32 символа base32. BitTorrent v2 (urn:btmh) не поддерживается: qBittorrent
// в /api/v2/torrents/info всё равно отдаёт v1-хеш для гибридных торрентов.
func ParseMagnet(raw string) (infoHash string, name string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("torrent: не удалось разобрать magnet: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "magnet") {
		return "", "", fmt.Errorf("torrent: ожидалась схема magnet, получено %q", u.Scheme)
	}
	q := u.Query()
	name = q.Get("dn")

	for _, xt := range q["xt"] {
		const prefix = "urn:btih:"
		if len(xt) <= len(prefix) || !strings.EqualFold(xt[:len(prefix)], prefix) {
			continue
		}
		h, err := normalizeInfoHash(xt[len(prefix):])
		if err != nil {
			continue
		}
		return h, name, nil
	}
	return "", name, ErrNoInfoHash
}

// normalizeInfoHash приводит hex- и base32-представления к hex в нижнем регистре.
func normalizeInfoHash(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch len(s) {
	case 40:
		b, err := hex.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("torrent: некорректный hex infohash: %w", err)
		}
		return hex.EncodeToString(b), nil
	case 32:
		b, err := base32.StdEncoding.DecodeString(strings.ToUpper(s))
		if err != nil {
			return "", fmt.Errorf("torrent: некорректный base32 infohash: %w", err)
		}
		return hex.EncodeToString(b), nil
	default:
		return "", fmt.Errorf("torrent: неожиданная длина infohash: %d", len(s))
	}
}
