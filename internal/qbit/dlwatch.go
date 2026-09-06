package qbit

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// DirectNotifier пишет в личку тому, кто добавил торрент.
// Интерфейс, а не *tgnotify.Notifier, чтобы воркер тестировался без сети.
type DirectNotifier interface {
	NotifyDownloaded(ctx context.Context, telegramID, torrentName string) error
	// DirectEnabled сообщает, может ли бот вообще писать в личку. Без токена
	// не может — и тогда наблюдать не за чем: единственный результат работы
	// воркера, личное сообщение, отправить будет некому.
	DirectEnabled() bool
}

// TorrentLister отдаёт список торрентов с прогрессом. Интерфейс нужен по той
// же причине — тест воркера не должен поднимать qBittorrent.
type TorrentLister interface {
	TorrentsInfo(ctx context.Context) ([]TorrentInfo, error)
}

// Watched — торрент, за загрузкой которого следим, и тот, кому о ней сообщить.
type Watched struct {
	InfoHash   string
	Name       string
	TelegramID string
	// Username нужен только журналу: разбирать, кому не дошло сообщение,
	// удобнее по нику, чем по числовому идентификатору.
	Username string
	// addedAt — когда взяли под наблюдение. Заполняется самим воркером.
	addedAt time.Time
	// misses — сколько опросов подряд торрента не было в ответе qBittorrent.
	// Заполняется самим воркером, см. dropMissing.
	misses int
}

const (
	// DefaultPollInterval — как часто опрашивается прогресс загрузок.
	DefaultPollInterval = 15 * time.Second

	// pollTimeout ограничивает один опрос. Без своего срока опрос висел бы
	// до таймаута транспорта, и тикер копил бы очередь.
	pollTimeout = 30 * time.Second

	// notifyTimeout ограничивает отправку одного личного сообщения.
	notifyTimeout = 30 * time.Second

	// maxMisses — сколько опросов подряд торрента может не быть в ответе
	// qBittorrent, прежде чем наблюдение снимается.
	//
	// Не один, а три, потому что пропуск не всегда означает удаление.
	// Торрент могли добавить в тот момент, когда ответ уже был собран, но
	// ещё не прочитан, — в этом ответе его нет законно. Три промаха подряд
	// такую случайность исключают, а удаление всё равно замечается за
	// три четверти минуты.
	maxMisses = 3

	// watchTTL — предельный срок ожидания одной загрузки.
	//
	// Удалённый торрент снимается с наблюдения сразу (см. dropMissing), но
	// есть загрузки, которые остаются в qBittorrent и не заканчиваются
	// никогда: поставленные на паузу навсегда или добавленные мёртвой
	// магнит-ссылкой. Без срока такая запись держала бы цикл опроса живым
	// вечно и медленно заполняла бы хранилище, после чего новые торренты
	// перестали бы отслеживаться.
	//
	// Неделя: заведомо больше любой разумной загрузки и заведомо меньше
	// «навсегда». Истёкшая запись просто исчезает — сообщения не будет, и это
	// честнее, чем вечное ожидание.
	watchTTL = 7 * 24 * time.Hour

	// maxWatched — потолок хранилища.
	//
	// Хранилище живёт в памяти и наполняется по запросу резидента: за
	// один POST /torrents/add принимается до torrent.MaxRefs ссылок, и
	// повторять такой запрос никто не мешает. Без потолка десяток запросов
	// от скрипта резидента раздул бы карту до десятков тысяч записей,
	// которые воркер потом перебирал бы каждые пятнадцать секунд.
	//
	// Переполнение — не отказ: лишнее просто не отслеживается, и человек не
	// получит личное сообщение о конце загрузки. Сама загрузка идёт как шла.
	maxWatched = 512
)

// DownloadWatcher следит за торрентами, добавленными через портал, и пишет в
// личку тому, кто их добавил, когда загрузка дошла до конца.
//
// Устройство подчинено двум требованиям.
//
// Первое — воркер один. Опрашивать qBittorrent несколькими циклами незачем,
// а дублирующиеся циклы означали бы дублирующиеся сообщения. Поэтому цикл
// запускается под тем же мьютексом, что защищает хранилище: два одновременных
// добавления не могут развести две горутины.
//
// Второе — воркер работает только когда есть за чем следить. Он стартует на
// первом добавлении и выходит, как только хранилище опустело. На простое
// (а это почти всегда) шлюз не ходит в qBittorrent вообще. Без настроенного
// бота он не стартует никогда: сообщать о конце загрузки нечем.
//
// Хранилище намеренно только в памяти и намеренно не дублируется на диск.
// Личное сообщение «загрузилось» — приятная мелочь, а не учётная запись:
// потерять его при перезапуске шлюза не жалко, а вот тащить ради него
// таблицу, миграции и чистку протухших записей — цена несоразмерная.
type DownloadWatcher struct {
	client   TorrentLister
	notify   DirectNotifier
	log      *slog.Logger
	interval time.Duration
	// now — источник времени. Подменяется тестами: срок ожидания загрузки
	// измеряется днями, и ждать его по-настоящему невозможно.
	now func() time.Time

	// base — контекст жизни процесса. Хранится в структуре, а не приходит
	// параметром, потому что цикл запускается не вызовом метода Run, а чужим
	// HTTP-запросом: в момент старта передать контекст неоткуда. Поле
	// заполняется один раз, при создании, и больше не меняется — поэтому
	// мьютексом не защищено.
	base context.Context

	mu      sync.Mutex
	watched map[string]Watched
	// loopDone не nil, пока цикл работает; закрывается на его выходе.
	// Он же и есть признак «воркер уже запущен».
	loopDone chan struct{}
}

// NewDownloadWatcher создаёт воркер. interval <= 0 — опрос по умолчанию.
//
// ctx — контекст жизни процесса: по его отмене цикл опроса выходит. Он нужен
// уже здесь, а не при первом запуске, чтобы между созданием воркера и его
// готовностью не было окна, в котором добавленный торрент принимается в
// хранилище, но цикл не поднимается.
func NewDownloadWatcher(ctx context.Context, client TorrentLister, notify DirectNotifier,
	log *slog.Logger, interval time.Duration) *DownloadWatcher {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	return &DownloadWatcher{
		base: ctx, client: client, notify: notify, log: log, interval: interval,
		now: time.Now, watched: make(map[string]Watched),
	}
}

// Wait ждёт, пока цикл опроса выйдет.
//
// Вызывается при остановке шлюза, уже после отмены контекста: цикл выйдет на
// ближайшем select, а дождаться его нужно, чтобы процесс не завершился
// посреди отправки сообщения. Если воркер не работает — возвращается сразу.
func (w *DownloadWatcher) Wait() {
	w.mu.Lock()
	done := w.loopDone
	w.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Track берёт торренты под наблюдение и при необходимости поднимает воркер.
//
// Торренты без infohash пропускаются: сопоставить их с ответом qBittorrent
// нечем. Так бывает со ссылкой на .torrent по http — хеш там становится
// известен только самому qBittorrent, уже после скачивания файла.
//
// Торренты без адресата пропускаются тоже: смысл наблюдения — личное
// сообщение, а посылать его некому.
func (w *DownloadWatcher) Track(items ...Watched) {
	// Без бота вся работа воркера бессмысленна: он опрашивал бы qBittorrent
	// каждые пятнадцать секунд ради сообщения, которое некому отправить.
	if !w.notify.DirectEnabled() {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	for _, it := range items {
		hash := strings.ToLower(strings.TrimSpace(it.InfoHash))
		if hash == "" || it.TelegramID == "" {
			continue
		}
		if _, ok := w.watched[hash]; !ok && len(w.watched) >= maxWatched {
			w.log.Warn("список отслеживаемых загрузок переполнен, "+
				"о завершении этой сообщено не будет",
				"limit", maxWatched, "torrent", it.Name, "user", it.Username)
			continue
		}
		it.InfoHash = hash
		it.addedAt = w.now()
		w.watched[hash] = it
	}

	if len(w.watched) == 0 || w.loopDone != nil {
		return // следить не за чем или воркер уже работает
	}
	// Шлюз уже останавливается — поднимать цикл не за чем.
	if w.base.Err() != nil {
		return
	}

	done := make(chan struct{})
	w.loopDone = done
	w.log.Info("воркер загрузок запущен", "watched", len(w.watched),
		"interval", w.interval.String())
	go w.run(w.base, done)
}

// tracked сообщает, сколько торрентов сейчас под наблюдением.
func (w *DownloadWatcher) tracked() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.watched)
}

// Running сообщает, работает ли цикл опроса. Нужен тестам и только им:
// снаружи это состояние ничем не управляет.
func (w *DownloadWatcher) Running() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.loopDone != nil
}

// run — сам цикл опроса. Выходит по отмене контекста или когда следить
// становится не за чем.
func (w *DownloadWatcher) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.stop("остановка шлюза")
			return
		case <-ticker.C:
		}

		w.poll(ctx)
		w.dropStale()

		// Решение об остановке принимается под тем же мьютексом, что и
		// запуск в Track. Иначе торрент, добавленный между проверкой и
		// сбросом loopDone, остался бы в хранилище с уже вышедшим циклом —
		// и о его загрузке не узнал бы никто.
		w.mu.Lock()
		if len(w.watched) == 0 {
			w.loopDone = nil
			w.mu.Unlock()
			w.log.Info("все отслеживаемые загрузки завершены, воркер остановлен")
			return
		}
		w.mu.Unlock()
	}
}

// dropStale выбрасывает загрузки, которых мы ждём слишком долго.
func (w *DownloadWatcher) dropStale() {
	w.mu.Lock()
	cutoff := w.now().Add(-watchTTL)
	var dropped []Watched
	for hash, item := range w.watched {
		if item.addedAt.Before(cutoff) {
			dropped = append(dropped, item)
			delete(w.watched, hash)
		}
	}
	w.mu.Unlock()

	for _, item := range dropped {
		w.log.Warn("загрузка не завершилась за отведённый срок, наблюдение снято",
			"torrent", item.Name, "user", item.TelegramID,
			"username", item.Username, "ttl", watchTTL.String())
	}
}

// stop снимает признак работающего цикла.
func (w *DownloadWatcher) stop(reason string) {
	w.mu.Lock()
	left := len(w.watched)
	w.loopDone = nil
	w.mu.Unlock()
	w.log.Info("воркер загрузок остановлен", "reason", reason, "watched", left)
}

// poll спрашивает у qBittorrent прогресс и разбирает завершившиеся загрузки.
func (w *DownloadWatcher) poll(ctx context.Context) {
	if w.tracked() == 0 {
		return
	}

	// Свой срок на запрос: контекст здесь живёт до конца процесса, и без
	// ограничения зависший опрос держал бы цикл вечно.
	reqCtx, cancel := context.WithTimeout(ctx, pollTimeout)
	infos, err := w.client.TorrentsInfo(reqCtx)
	cancel()
	if err != nil {
		// Опрос не удался — не беда: следующий тик повторит. Ошибку не
		// шумим на остановке, там она ожидаема.
		if ctx.Err() == nil {
			w.log.Warn("не удалось опросить загрузки qBittorrent", "error", err)
		}
		return
	}

	w.dropMissing(infos)

	for _, info := range infos {
		// Фильтр по своему хранилищу: в qBittorrent торренты добавляют и
		// мимо портала (RSS, папка автозагрузки, прямой доступ), и о них
		// сообщать некому.
		if info.Progress < 1 {
			continue
		}
		hash := strings.ToLower(info.Hash)

		w.mu.Lock()
		item, ok := w.watched[hash]
		delete(w.watched, hash)
		w.mu.Unlock()
		if !ok {
			continue
		}

		name := item.Name
		if info.Name != "" {
			name = info.Name // qBittorrent знает точное имя, magnet — только dn
		}
		w.announce(ctx, item, name)
	}
}

// dropMissing снимает наблюдение с торрентов, которых больше нет в qBittorrent.
//
// Запрос отдаёт все торренты сразу, поэтому отсутствие в ответе означает
// удаление. Ждать удалённой загрузки бессмысленно: она не закончится никогда,
// а запись держала бы цикл опроса живым и занимала бы место в хранилище до
// истечения watchTTL — то есть неделю.
//
// Снимаем не с первого промаха, а с maxMisses подряд: одиночный пропуск может
// означать не удаление, а торрент, добавленный ровно между сбором ответа и
// его чтением. Найденный торрент обнуляет счётчик, поэтому «подряд» здесь
// именно подряд.
func (w *DownloadWatcher) dropMissing(infos []TorrentInfo) {
	alive := make(map[string]struct{}, len(infos))
	for _, info := range infos {
		alive[strings.ToLower(info.Hash)] = struct{}{}
	}

	w.mu.Lock()
	var dropped []Watched
	for hash, item := range w.watched {
		if _, ok := alive[hash]; ok {
			if item.misses > 0 {
				item.misses = 0
				w.watched[hash] = item
			}
			continue
		}
		item.misses++
		if item.misses < maxMisses {
			w.watched[hash] = item
			continue
		}
		dropped = append(dropped, item)
		delete(w.watched, hash)
	}
	w.mu.Unlock()

	for _, item := range dropped {
		w.log.Info("торрента больше нет в qBittorrent, наблюдение снято",
			"torrent", item.Name, "user", item.TelegramID, "username", item.Username)
	}
}

// announce отправляет личное сообщение о законченной загрузке.
//
// Неудача только логируется, и это осознанно: самый частый отказ — человек ни
// разу не писал боту, и Telegram запрещает боту начинать разговор первым.
// Чинить это шлюз не может, а терять из-за необязательного уведомления что-то
// ещё — не за что.
func (w *DownloadWatcher) announce(ctx context.Context, item Watched, name string) {
	sendCtx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	if err := w.notify.NotifyDownloaded(sendCtx, item.TelegramID, name); err != nil {
		w.log.Warn("не удалось сообщить резиденту о завершённой загрузке",
			"error", err, "user", item.TelegramID, "username", item.Username,
			"torrent", name)
		return
	}
	w.log.Info("резиденту сообщено о завершённой загрузке",
		"user", item.TelegramID, "username", item.Username, "torrent", name)
}
