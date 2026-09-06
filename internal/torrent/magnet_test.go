package torrent_test

import (
	"errors"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/torrent"
)

func TestParseMagnetHex(t *testing.T) {
	link := "magnet:?xt=urn:btih:C12FE1C06BBA254A9DC9F519B335AA7C1367A88A&dn=ubuntu.iso&tr=udp%3A%2F%2Ftr"

	hash, name, err := torrent.ParseMagnet(link)
	if err != nil {
		t.Fatalf("ParseMagnet: %v", err)
	}
	if hash != "c12fe1c06bba254a9dc9f519b335aa7c1367a88a" {
		t.Fatalf("infohash = %q", hash)
	}
	if name != "ubuntu.iso" {
		t.Fatalf("имя = %q", name)
	}
}

// Старые трекеры отдают infohash в base32 — его нужно приводить к hex,
// иначе сопоставление с журналом qBittorrent развалится.
func TestParseMagnetBase32(t *testing.T) {
	hex40 := "c12fe1c06bba254a9dc9f519b335aa7c1367a88a"
	base32Form := "YEX6DQDLXISUVHOJ6UM3GNNKPQJWPKEK"

	hash, _, err := torrent.ParseMagnet("magnet:?xt=urn:btih:" + base32Form)
	if err != nil {
		t.Fatalf("ParseMagnet: %v", err)
	}
	if hash != hex40 {
		t.Fatalf("infohash = %q, ожидался %q", hash, hex40)
	}
}

func TestParseMagnetPicksBtihAmongSeveralXT(t *testing.T) {
	link := "magnet:?xt=urn:ed2k:aaa&xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a"

	hash, _, err := torrent.ParseMagnet(link)
	if err != nil {
		t.Fatalf("ParseMagnet: %v", err)
	}
	if hash != "c12fe1c06bba254a9dc9f519b335aa7c1367a88a" {
		t.Fatalf("infohash = %q", hash)
	}
}

func TestParseMagnetWithoutBtih(t *testing.T) {
	_, name, err := torrent.ParseMagnet("magnet:?dn=only-name&xt=urn:btmh:1220abcd")
	if !errors.Is(err, torrent.ErrNoInfoHash) {
		t.Fatalf("ожидалась ErrNoInfoHash, получено %v", err)
	}
	// Имя всё равно возвращаем: по нему торрент можно найти в журнале.
	if name != "only-name" {
		t.Fatalf("имя = %q", name)
	}
}

func TestParseMagnetRejectsWrongScheme(t *testing.T) {
	if _, _, err := torrent.ParseMagnet("https://example.org/a.torrent"); err == nil {
		t.Fatal("ожидалась ошибка на не-magnet ссылке")
	}
}

func TestParseMagnetRejectsBadHash(t *testing.T) {
	// "1" не входит в алфавит base32 (A-Z, 2-7), "gg" — не hex.
	for _, bad := range []string{"zz", "11111111111111111111111111111111", "gg2fe1c06bba254a9dc9f519b335aa7c1367a88a"} {
		if _, _, err := torrent.ParseMagnet("magnet:?xt=urn:btih:" + bad); err == nil {
			t.Fatalf("хеш %q принят", bad)
		}
	}
}
