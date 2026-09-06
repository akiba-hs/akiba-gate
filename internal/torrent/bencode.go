// Package torrent извлекает идентификаторы торрентов из того, что резидент
// отправляет в qBittorrent: из magnet-ссылок и из .torrent-файлов.
//
// Полноценный декодер bencode здесь не нужен и вреден: чтобы посчитать
// infohash, требуется не разобранная структура, а точные границы значения
// ключа "info" в исходных байтах. Поэтому реализован сканер, который умеет
// пропускать значения и запоминать смещения.
package torrent

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// ErrMalformed — файл не является корректным bencode.
var ErrMalformed = errors.New("torrent: некорректный bencode")

// maxDepth ограничивает вложенность структур.
//
// Сканер рекурсивный, а переполнение стека в Go — это fatal error, которую
// не перехватывает recover(). Без ограничения файл из одних байтов 'l'
// гарантированно роняет весь процесс, а прислать его может любой резидент.
// Реальные торренты глубже 5-6 уровней не бывают.
const maxDepth = 64

// entry — одна пара ключ/значение словаря с границами значения в буфере.
type entry struct {
	key      string
	valStart int
	valEnd   int
}

// InfoFromTorrentFile считает infohash (BitTorrent v1) и достаёт имя торрента.
//
// infohash v1 — это SHA-1 от точных байтов словаря "info", как он лежит в
// файле. Пересобирать словарь нельзя: любая нормализация изменит хеш.
func InfoFromTorrentFile(data []byte) (infoHash string, name string, err error) {
	entries, err := dictEntries(data, 0, 0)
	if err != nil {
		return "", "", fmt.Errorf("%w: корневой словарь: %s", ErrMalformed, err)
	}
	info, ok := findEntry(entries, "info")
	if !ok {
		return "", "", fmt.Errorf("%w: нет ключа info", ErrMalformed)
	}

	sum := sha1.Sum(data[info.valStart:info.valEnd])
	infoHash = hex.EncodeToString(sum[:])

	// Имя не обязательно: без него сообщение в чат остаётся безымянным,
	// но добавление торрента не срывается, поэтому ошибку здесь глотаем.
	// depth = 1, а не 0: словарь info лежит внутри корневого, и обнулённый
	// счётчик давал бы на вложенный разбор ещё один полный бюджет глубины.
	if infoEntries, err := dictEntries(data, info.valStart, 1); err == nil {
		if nameEntry, ok := findEntry(infoEntries, "name"); ok {
			if s, _, err := scanString(data, nameEntry.valStart); err == nil {
				name = s
			}
		}
	}
	return infoHash, name, nil
}

func findEntry(entries []entry, key string) (entry, bool) {
	for _, e := range entries {
		if e.key == key {
			return e, true
		}
	}
	return entry{}, false
}

// dictEntries разбирает словарь, начинающийся с позиции start.
func dictEntries(b []byte, start, depth int) ([]entry, error) {
	if depth > maxDepth {
		return nil, errors.New("превышена допустимая вложенность")
	}
	if start >= len(b) || b[start] != 'd' {
		return nil, errors.New("ожидался словарь")
	}
	i := start + 1
	var out []entry
	for {
		if i >= len(b) {
			return nil, errors.New("словарь не закрыт")
		}
		if b[i] == 'e' {
			return out, nil
		}
		key, next, err := scanString(b, i)
		if err != nil {
			return nil, fmt.Errorf("ключ словаря: %w", err)
		}
		valStart := next
		valEnd, err := scanValue(b, valStart, depth+1)
		if err != nil {
			return nil, fmt.Errorf("значение ключа %q: %w", key, err)
		}
		out = append(out, entry{key: key, valStart: valStart, valEnd: valEnd})
		i = valEnd
	}
}

// scanValue возвращает индекс сразу за значением, начинающимся с позиции i.
func scanValue(b []byte, i, depth int) (int, error) {
	if depth > maxDepth {
		return 0, errors.New("превышена допустимая вложенность")
	}
	if i >= len(b) {
		return 0, errors.New("неожиданный конец данных")
	}
	switch c := b[i]; {
	case c == 'i': // целое: i<число>e
		end := indexByteFrom(b, i+1, 'e')
		if end < 0 {
			return 0, errors.New("целое не закрыто")
		}
		if _, err := strconv.ParseInt(string(b[i+1:end]), 10, 64); err != nil {
			return 0, fmt.Errorf("некорректное целое: %w", err)
		}
		return end + 1, nil

	case c == 'l' || c == 'd': // список или словарь
		i++
		for {
			if i >= len(b) {
				return 0, errors.New("составное значение не закрыто")
			}
			if b[i] == 'e' {
				return i + 1, nil
			}
			if c == 'd' {
				// Ключ словаря обязан быть строкой.
				var err error
				if _, i, err = scanString(b, i); err != nil {
					return 0, err
				}
			}
			var err error
			if i, err = scanValue(b, i, depth+1); err != nil {
				return 0, err
			}
		}

	case c >= '0' && c <= '9': // строка: <длина>:<байты>
		_, end, err := scanString(b, i)
		return end, err

	default:
		return 0, fmt.Errorf("неожиданный байт %q на позиции %d", c, i)
	}
}

// scanString читает bencode-строку и возвращает её значение и позицию за ней.
func scanString(b []byte, i int) (string, int, error) {
	colon := indexByteFrom(b, i, ':')
	if colon < 0 {
		return "", 0, errors.New("строка без разделителя ':'")
	}
	n, err := strconv.Atoi(string(b[i:colon]))
	if err != nil {
		return "", 0, fmt.Errorf("некорректная длина строки: %w", err)
	}
	if n < 0 {
		return "", 0, errors.New("отрицательная длина строки")
	}
	start := colon + 1
	// Сравнение через вычитание, а не start+n: сумма переполняется на длине
	// вроде 9223372036854775807 и проверка границ становится бесполезной.
	if n > len(b)-start {
		return "", 0, errors.New("строка выходит за границы данных")
	}
	return string(b[start : start+n]), start + n, nil
}

func indexByteFrom(b []byte, from int, c byte) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
