package qbit

import "time"

// Крючки для тестов. Отдельный файл с суффиксом _test.go: в собранный
// бинарник он не попадает.

// MaxWatchedForTest — потолок хранилища воркера загрузок.
const MaxWatchedForTest = maxWatched

// WatchTTLForTest — срок ожидания одной загрузки.
const WatchTTLForTest = watchTTL

// Tracked сообщает, сколько торрентов под наблюдением.
func (w *DownloadWatcher) Tracked() int { return w.tracked() }

// SetClockForTest подменяет источник времени: ждать неделю в тесте нельзя.
func (w *DownloadWatcher) SetClockForTest(now func() time.Time) {
	w.mu.Lock()
	w.now = now
	w.mu.Unlock()
}

// MaxMissesForTest — сколько опросов подряд торрента может не быть в ответе
// qBittorrent, прежде чем наблюдение снимается.
const MaxMissesForTest = maxMisses
