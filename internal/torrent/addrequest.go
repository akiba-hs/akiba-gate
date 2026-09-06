package torrent

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

// Source описывает, откуда взялся торрент в запросе резидента.
type Source string

const (
	SourceMagnet Source = "magnet" // magnet-ссылка
	SourceFile   Source = "file"   // загруженный .torrent
	SourceURL    Source = "url"    // ссылка на .torrent по http(s)
)

// Ref — одна распознанная единица «резидент добавил вот это».
//
// InfoHash может быть пустым: для ссылки на .torrent по http(s) хеш становится
// известен только после того, как файл скачает сам qBittorrent. В этом случае
// в чат уходит только имя.
type Ref struct {
	InfoHash string
	Name     string
	Source   Source
	Raw      string // исходная ссылка или имя файла — для разбора инцидентов
}

// MaxAddBodySize ограничивает объём тела запроса, который шлюз готов разобрать
// ради атрибуции. Всё, что больше, проксируется без разбора: торрент-файл на
// десятки мегабайт — это уже не .torrent, а чья-то ошибка или атака.
const MaxAddBodySize = 32 << 20 // 32 МиБ

// MaxRefs ограничивает число распознанных единиц в одном запросе.
//
// Лимита по объёму тела недостаточно: в 32 МиБ помещается несколько сотен
// тысяч magnet-ссылок, а каждая — это отдельная запись в SQLite, где пул
// ограничен одним соединением. Один такой запрос от резидента занял бы базу
// на минуты, остановив портал и наблюдателя за
// журналом, и оставил бы сотни тысяч строк без infohash, которые
// частичный уникальный индекс намеренно не схлопывает.
//
// Всё, что сверх лимита, проксируется без атрибуции: терять загрузку
// резидента ради собственного журнала нельзя.
const MaxRefs = 256

// ParseAddRequest распознаёт тело запроса POST /api/v2/torrents/add.
//
// qBittorrent принимает и multipart/form-data (когда есть файлы), и обычную
// urlencoded-форму (когда только ссылки). Поддерживаем оба варианта.
//
// Ошибка разбора не должна ломать проксирование: вызывающий код обязан
// пропустить запрос дальше, даже если атрибутировать его не удалось.
func ParseAddRequest(contentType string, body []byte) ([]Ref, error) {
	refs, err := parseAddRequest(contentType, body)
	return capRefs(refs), err
}

// capRefs обрезает список до MaxRefs, сохраняя порядок.
func capRefs(refs []Ref) []Ref {
	if len(refs) <= MaxRefs {
		return refs
	}
	return refs[:MaxRefs]
}

func parseAddRequest(contentType string, body []byte) ([]Ref, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("torrent: некорректный Content-Type %q: %w", contentType, err)
	}

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		boundary := params["boundary"]
		if boundary == "" {
			return nil, fmt.Errorf("torrent: multipart без boundary")
		}
		return parseMultipart(body, boundary)

	case mediaType == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, fmt.Errorf("torrent: некорректная форма: %w", err)
		}
		return refsFromURLs(values.Get("urls")), nil

	default:
		return nil, fmt.Errorf("torrent: неподдерживаемый Content-Type %q", mediaType)
	}
}

func parseMultipart(body []byte, boundary string) ([]Ref, error) {
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var refs []Ref

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return refs, nil
		}
		if err != nil {
			// Возвращаем то, что успели распознать: частичная атрибуция
			// лучше, чем никакой.
			return refs, fmt.Errorf("torrent: разбор multipart: %w", err)
		}

		switch part.FormName() {
		case "urls":
			data, err := io.ReadAll(io.LimitReader(part, MaxAddBodySize))
			if err != nil {
				return refs, fmt.Errorf("torrent: чтение поля urls: %w", err)
			}
			refs = append(refs, refsFromURLs(string(data))...)

		case "torrents", "fileselect[]":
			data, err := io.ReadAll(io.LimitReader(part, MaxAddBodySize))
			if err != nil {
				return refs, fmt.Errorf("torrent: чтение файла: %w", err)
			}
			hash, name, err := InfoFromTorrentFile(data)
			if err != nil {
				// Файл битый — фиксируем факт, но не теряем резидента.
				refs = append(refs, Ref{Name: part.FileName(), Source: SourceFile, Raw: part.FileName()})
				continue
			}
			if name == "" {
				name = part.FileName()
			}
			refs = append(refs, Ref{InfoHash: hash, Name: name, Source: SourceFile, Raw: part.FileName()})
		}
		_ = part.Close()
	}
}

// refsFromURLs разбирает поле urls: ссылки разделены переводами строк.
func refsFromURLs(raw string) []Ref {
	var refs []Ref
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "magnet:") {
			hash, name, err := ParseMagnet(line)
			if err != nil && hash == "" {
				refs = append(refs, Ref{Name: name, Source: SourceMagnet, Raw: line})
				continue
			}
			refs = append(refs, Ref{InfoHash: hash, Name: name, Source: SourceMagnet, Raw: line})
			continue
		}
		// Ссылка на .torrent без хеша: сопоставить её с загрузкой нечем,
		// поэтому в чат такая не попадает.
		refs = append(refs, Ref{Name: fileNameFromURL(line), Source: SourceURL, Raw: line})
	}
	return refs
}

// fileNameFromURL достаёт последний сегмент пути — обычно это имя .torrent.
func fileNameFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	last := segments[len(segments)-1]
	if last == "" {
		return raw
	}
	if decoded, err := url.PathUnescape(last); err == nil {
		last = decoded
	}
	return strings.TrimSuffix(last, ".torrent")
}
