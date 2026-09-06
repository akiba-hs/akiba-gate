package torrent_test

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/testsupport"
	"github.com/akiba-hs/akiba-gate/internal/torrent"
)

func TestInfoFromTorrentFile(t *testing.T) {
	const name = "Ubuntu 24.04 LTS"
	pieces := "01234567890123456789" // 20 байт, как один SHA-1
	file := testsupport.TorrentFile(name, 262144, pieces)

	// Ожидаемый хеш считаем независимо от кода — от точных байтов словаря info.
	want := sha1.Sum(testsupport.InfoDictOf(name, 262144, pieces))

	gotHash, gotName, err := torrent.InfoFromTorrentFile(file)
	if err != nil {
		t.Fatalf("InfoFromTorrentFile: %v", err)
	}
	if gotHash != hex.EncodeToString(want[:]) {
		t.Fatalf("infohash = %s, ожидался %s", gotHash, hex.EncodeToString(want[:]))
	}
	if gotName != name {
		t.Fatalf("имя = %q, ожидалось %q", gotName, name)
	}
}

func TestInfoFromTorrentFileHandlesUnicodeName(t *testing.T) {
	const name = "Тайна третьей планеты"
	file := testsupport.TorrentFile(name, 16384, "aaaaaaaaaaaaaaaaaaaa")

	_, gotName, err := torrent.InfoFromTorrentFile(file)
	if err != nil {
		t.Fatalf("InfoFromTorrentFile: %v", err)
	}
	if gotName != name {
		t.Fatalf("имя = %q, ожидалось %q", gotName, name)
	}
}

// Проверяем, что хеш считается именно от вложенного словаря, а не от файла:
// два файла с разными анонсами, но одинаковым info дают один infohash.
func TestInfoHashIgnoresOuterFields(t *testing.T) {
	info := string(testsupport.InfoDictOf("same", 1024, "bbbbbbbbbbbbbbbbbbbb"))
	a := []byte("d8:announce11:http://a/an4:info" + info + "e")
	b := []byte("d8:announce12:http://bb/an4:info" + info + "13:creation datei1e" + "e")

	ha, _, err := torrent.InfoFromTorrentFile(a)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	hb, _, err := torrent.InfoFromTorrentFile(b)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if ha != hb {
		t.Fatalf("хеши разошлись: %s и %s", ha, hb)
	}
}

func TestInfoFromTorrentFileRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"пусто":               "",
		"не словарь":          "l4:spame",
		"нет info":            "d8:announce3:abce",
		"словарь не закрыт":   "d4:infod4:name3:abc",
		"битая длина строки":  "d4:info d1:ae",
		"строка за границами": "d4:infod4:name99:short" + "ee",
		"битое целое":         "d4:infod6:lengthiXXeee",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := torrent.InfoFromTorrentFile([]byte(data)); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

// Вложенные списки и словари внутри info не должны сбивать сканер:
// у многофайловых торрентов там лежит список files.
func TestInfoFromTorrentFileHandlesNestedStructures(t *testing.T) {
	info := "d5:filesld6:lengthi10e4:pathl3:dir4:fileeee4:name3:abce"
	file := []byte("d4:info" + info + "e")

	hash, name, err := torrent.InfoFromTorrentFile(file)
	if err != nil {
		t.Fatalf("InfoFromTorrentFile: %v", err)
	}
	if name != "abc" {
		t.Fatalf("имя = %q", name)
	}
	want := sha1.Sum([]byte(info))
	if hash != hex.EncodeToString(want[:]) {
		t.Fatalf("infohash = %s", hash)
	}
}

// Сканер рекурсивный, а переполнение стека в Go — это fatal error, которую
// не перехватывает recover(). Файл из одних байтов 'l' прислал бы любой
// резидент, и шлюз падал бы целиком.
func TestInfoFromTorrentFileRejectsDeepNesting(t *testing.T) {
	deep := []byte("d4:info")
	for i := 0; i < 100000; i++ {
		deep = append(deep, 'l')
	}

	if _, _, err := torrent.InfoFromTorrentFile(deep); err == nil {
		t.Fatal("глубокая вложенность принята")
	}
}

// Длина строки близкая к MaxInt64 переполняет сумму start+n, и наивная
// проверка границ пропускает срез с отрицательным индексом.
func TestInfoFromTorrentFileRejectsOverflowingStringLength(t *testing.T) {
	for _, data := range []string{
		"d4:info9223372036854775807:xe",
		"d9223372036854775807:infod4:name1:ae",
		"d4:infod4:name9223372036854775806:xee",
	} {
		if _, _, err := torrent.InfoFromTorrentFile([]byte(data)); err == nil {
			t.Fatalf("длина с переполнением принята: %q", data)
		}
	}
}

// Разумная вложенность (многофайловый торрент со списком путей) обязана
// продолжать работать.
func TestInfoFromTorrentFileAcceptsReasonableNesting(t *testing.T) {
	info := "d5:filesld6:lengthi1e4:pathl1:a1:b1:ceee4:name1:xe"
	if _, name, err := torrent.InfoFromTorrentFile([]byte("d4:info" + info + "e")); err != nil || name != "x" {
		t.Fatalf("err=%v name=%q", err, name)
	}
}
