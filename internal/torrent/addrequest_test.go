package torrent_test

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/akiba-hs/akiba-gate/internal/testsupport"
	"github.com/akiba-hs/akiba-gate/internal/torrent"
)

// buildMultipart собирает тело в том же виде, в каком его шлёт WebUI qBittorrent.
func buildMultipart(t *testing.T, urls string, files map[string][]byte) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if urls != "" {
		if err := w.WriteField("urls", urls); err != nil {
			t.Fatalf("поле urls: %v", err)
		}
	}
	for name, data := range files {
		part, err := w.CreateFormFile("torrents", name)
		if err != nil {
			t.Fatalf("файл %s: %v", name, err)
		}
		if _, err := part.Write(data); err != nil {
			t.Fatalf("запись файла: %v", err)
		}
	}
	// Настройки, которые qBittorrent шлёт вместе с торрентом; нас они
	// не интересуют и не должны мешать разбору.
	_ = w.WriteField("savepath", "/downloads")
	_ = w.WriteField("paused", "false")
	if err := w.Close(); err != nil {
		t.Fatalf("закрытие multipart: %v", err)
	}
	return w.FormDataContentType(), buf.Bytes()
}

func TestParseAddRequestMultipartFile(t *testing.T) {
	file := testsupport.TorrentFile("Ubuntu 24.04", 262144, "01234567890123456789")
	ct, body := buildMultipart(t, "", map[string][]byte{"ubuntu.torrent": file})

	refs, err := torrent.ParseAddRequest(ct, body)
	if err != nil {
		t.Fatalf("ParseAddRequest: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("получено %d ссылок, ожидалась 1: %+v", len(refs), refs)
	}
	if refs[0].Source != torrent.SourceFile {
		t.Fatalf("source = %q", refs[0].Source)
	}
	if refs[0].Name != "Ubuntu 24.04" {
		t.Fatalf("имя = %q (должно браться из info, а не из имени файла)", refs[0].Name)
	}
	if len(refs[0].InfoHash) != 40 {
		t.Fatalf("infohash = %q", refs[0].InfoHash)
	}
}

func TestParseAddRequestMultipartUrls(t *testing.T) {
	urls := strings.Join([]string{
		"magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=first",
		"https://example.org/files/second.torrent",
	}, "\n")
	ct, body := buildMultipart(t, urls, nil)

	refs, err := torrent.ParseAddRequest(ct, body)
	if err != nil {
		t.Fatalf("ParseAddRequest: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("получено %d ссылок: %+v", len(refs), refs)
	}
	if refs[0].Source != torrent.SourceMagnet || refs[0].InfoHash == "" {
		t.Fatalf("magnet разобран неверно: %+v", refs[0])
	}
	// У ссылки на .torrent хеша ещё нет — он появится из журнала qBittorrent.
	if refs[1].Source != torrent.SourceURL || refs[1].InfoHash != "" {
		t.Fatalf("ссылка разобрана неверно: %+v", refs[1])
	}
	if refs[1].Name != "second" {
		t.Fatalf("имя из URL = %q, ожидалось second", refs[1].Name)
	}
}

func TestParseAddRequestUrlencoded(t *testing.T) {
	body := []byte("urls=magnet%3A%3Fxt%3Durn%3Abtih%3Ac12fe1c06bba254a9dc9f519b335aa7c1367a88a&savepath=%2Fd")

	refs, err := torrent.ParseAddRequest("application/x-www-form-urlencoded", body)
	if err != nil {
		t.Fatalf("ParseAddRequest: %v", err)
	}
	if len(refs) != 1 || refs[0].InfoHash != "c12fe1c06bba254a9dc9f519b335aa7c1367a88a" {
		t.Fatalf("разобрано неверно: %+v", refs)
	}
}

func TestParseAddRequestMixedFilesAndUrls(t *testing.T) {
	file := testsupport.TorrentFile("From File", 16384, "aaaaaaaaaaaaaaaaaaaa")
	ct, body := buildMultipart(t,
		"magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=from-magnet",
		map[string][]byte{"a.torrent": file})

	refs, err := torrent.ParseAddRequest(ct, body)
	if err != nil {
		t.Fatalf("ParseAddRequest: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("получено %d ссылок: %+v", len(refs), refs)
	}
}

// Битый .torrent не должен терять резидента: факт добавления фиксируем,
// пусть и без хеша.
func TestParseAddRequestBrokenFileStillRecorded(t *testing.T) {
	ct, body := buildMultipart(t, "", map[string][]byte{"broken.torrent": []byte("не bencode")})

	refs, err := torrent.ParseAddRequest(ct, body)
	if err != nil {
		t.Fatalf("ParseAddRequest: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("получено %d ссылок: %+v", len(refs), refs)
	}
	if refs[0].InfoHash != "" || refs[0].Name != "broken.torrent" {
		t.Fatalf("ожидалась запись без хеша с именем файла, получено %+v", refs[0])
	}
}

func TestParseAddRequestRejectsUnknownContentType(t *testing.T) {
	if _, err := torrent.ParseAddRequest("application/json", []byte("{}")); err == nil {
		t.Fatal("ожидалась ошибка на неподдерживаемом типе")
	}
	if _, err := torrent.ParseAddRequest("", nil); err == nil {
		t.Fatal("ожидалась ошибка на пустом Content-Type")
	}
	if _, err := torrent.ParseAddRequest("multipart/form-data", nil); err == nil {
		t.Fatal("ожидалась ошибка на multipart без boundary")
	}
}

func TestParseAddRequestIgnoresBlankLines(t *testing.T) {
	ct, body := buildMultipart(t, "\n\n  \nmagnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a\n\n", nil)

	refs, err := torrent.ParseAddRequest(ct, body)
	if err != nil {
		t.Fatalf("ParseAddRequest: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("получено %d ссылок: %+v", len(refs), refs)
	}
}

// В 32 МиБ тела помещаются сотни тысяч magnet-ссылок, а каждая — это отдельная
// запись в SQLite с пулом в одно соединение. Один такой запрос от резидента
// занял бы базу на минуты и остановил портал, наблюдателя за журналом и
// отправку в чат. Лимита по объёму тела для этого недостаточно.
func TestParseAddRequestCapsNumberOfRefs(t *testing.T) {
	var b strings.Builder
	b.WriteString("urls=")
	for i := 0; i < torrent.MaxRefs*3; i++ {
		if i > 0 {
			b.WriteString("%0A")
		}
		_, _ = fmt.Fprintf(&b, "magnet:?xt=urn:btih:%040x", i)
	}

	refs, err := torrent.ParseAddRequest("application/x-www-form-urlencoded", []byte(b.String()))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(refs) != torrent.MaxRefs {
		t.Fatalf("распознано %d ссылок, ожидалось не больше %d", len(refs), torrent.MaxRefs)
	}
	// Обрезаем хвост, а не начало: первые ссылки должны сохраниться.
	if refs[0].InfoHash != fmt.Sprintf("%040x", 0) {
		t.Errorf("порядок нарушен, первая ссылка = %q", refs[0].InfoHash)
	}
}
