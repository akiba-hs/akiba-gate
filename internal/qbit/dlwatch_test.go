package qbit_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/qbit"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeLister — qBittorrent, отвечающий заранее заданным списком.
type fakeLister struct {
	mu       sync.Mutex
	torrents []qbit.TorrentInfo
	err      error
	calls    atomic.Int32
	// concurrent считает, сколько опросов идёт одновременно: воркер обязан
	// быть один, и второй параллельный опрос — это второй воркер.
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	// delay растягивает опрос, чтобы параллельные вызовы успели наложиться.
	delay time.Duration
}

func (f *fakeLister) TorrentsInfo(ctx context.Context) ([]qbit.TorrentInfo, error) {
	f.calls.Add(1)
	n := f.inFlight.Add(1)
	for {
		max := f.maxInFlight.Load()
		if n <= max || f.maxInFlight.CompareAndSwap(max, n) {
			break
		}
	}
	defer f.inFlight.Add(-1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return append([]qbit.TorrentInfo(nil), f.torrents...), nil
}

func (f *fakeLister) set(items ...qbit.TorrentInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.torrents, f.err = items, nil
}

func (f *fakeLister) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// fakeDM — бот, пишущий в личку. Запоминает адресатов и темы сообщений.
type fakeDM struct {
	mu   sync.Mutex
	sent []string // "telegramID|torrent"
	err  error
	// off изображает шлюз без токена бота: писать в личку нечем.
	off bool
}

func (f *fakeDM) DirectEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.off
}

func (f *fakeDM) NotifyDownloaded(_ context.Context, telegramID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, telegramID+"|"+name)
	return nil
}

func (f *fakeDM) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

// newWatcher поднимает воркер с очень частым опросом: тест не должен ждать
// реальные пятнадцать секунд.
func newWatcher(t *testing.T, lister *fakeLister, dm *fakeDM) (*qbit.DownloadWatcher, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w := qbit.NewDownloadWatcher(ctx, lister, dm, quiet(), time.Millisecond)
	t.Cleanup(func() {
		cancel()
		done := make(chan struct{})
		go func() { defer close(done); w.Wait() }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("воркер не остановился после отмены контекста")
		}
	})
	return w, cancel
}

// trackRunning берёт торрент под наблюдение и дожидается, пока цикл не сделает
// хотя бы один опрос. Без этого проверка «воркер остановился» проходила бы и
// на воркере, который ещё не успел запуститься.
func trackRunning(t *testing.T, w *qbit.DownloadWatcher, lister *fakeLister, items ...qbit.Watched) {
	t.Helper()
	before := lister.calls.Load()
	w.Track(items...)
	if !w.Running() {
		t.Fatal("воркер не поднялся после добавления торрента")
	}
	waitFor(t, "первый опрос", func() bool { return lister.calls.Load() > before })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

func watched(hash, user string) qbit.Watched {
	return qbit.Watched{InfoHash: hash, Name: "торрент " + hash, TelegramID: user, Username: "u" + user}
}

// Главный сценарий: загрузка дошла до конца — автор получает личное сообщение,
// а торрент уходит из хранилища.
func TestWatcherNotifiesOnCompletedDownload(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	lister.set(qbit.TorrentInfo{Hash: "AABB", Name: "Ubuntu 24.04", Progress: 0.4})
	w.Track(watched("aabb", "42"))

	waitFor(t, "первый опрос", func() bool { return lister.calls.Load() > 0 })
	if got := dm.all(); len(got) != 0 {
		t.Fatalf("сообщение ушло до конца загрузки: %v", got)
	}

	lister.set(qbit.TorrentInfo{Hash: "AABB", Name: "Ubuntu 24.04", Progress: 1})
	waitFor(t, "сообщение о завершении", func() bool { return len(dm.all()) == 1 })

	if got := dm.all()[0]; got != "42|Ubuntu 24.04" {
		t.Fatalf("сообщение = %q, ожидалось адресату 42 про Ubuntu 24.04", got)
	}
	// Имя берём из ответа qBittorrent: в magnet-ссылке лежит dn, а он врёт
	// заметно чаще, чем то, что торрент показывает в клиенте.
	waitFor(t, "остановка опустевшего воркера", func() bool { return !w.Running() })
}

// Хранилище опустело — воркер обязан выключиться, а не крутить пустой опрос.
func TestWatcherStopsWhenStoreEmpties(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	lister.set(qbit.TorrentInfo{Hash: "aabb", Progress: 0.5})
	trackRunning(t, w, lister, watched("aabb", "42"))

	lister.set(qbit.TorrentInfo{Hash: "aabb", Progress: 1})
	waitFor(t, "воркер остановился", func() bool { return !w.Running() })

	// После остановки опросов быть не должно вовсе.
	before := lister.calls.Load()
	time.Sleep(30 * time.Millisecond)
	if after := lister.calls.Load(); after != before {
		t.Fatalf("остановленный воркер продолжает опрашивать: было %d, стало %d", before, after)
	}
}

// Второе добавление после остановки обязано поднять воркер заново.
func TestWatcherRestartsAfterIdle(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	lister.set(qbit.TorrentInfo{Hash: "aabb", Progress: 0.5})
	trackRunning(t, w, lister, watched("aabb", "42"))
	lister.set(qbit.TorrentInfo{Hash: "aabb", Progress: 1})
	waitFor(t, "первая остановка", func() bool { return !w.Running() })

	lister.set(qbit.TorrentInfo{Hash: "ccdd", Progress: 0.5})
	trackRunning(t, w, lister, watched("ccdd", "43"))
	lister.set(qbit.TorrentInfo{Hash: "ccdd", Progress: 1})
	waitFor(t, "второе сообщение", func() bool { return len(dm.all()) == 2 })
	waitFor(t, "вторая остановка", func() bool { return !w.Running() })
}

// Ключевое требование: воркер один. Несколько одновременных добавлений не
// должны развести две горутины опроса — иначе придут дубли сообщений.
func TestWatcherStaysSingleUnderConcurrentTracking(t *testing.T) {
	lister := &fakeLister{delay: 2 * time.Millisecond}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	// Все пятьдесят торрентов есть в qBittorrent и качаются: иначе они были
	// бы законно сняты с наблюдения, и цикл вышел бы раньше времени.
	infos := make([]qbit.TorrentInfo, 0, 50)
	for i := 0; i < 50; i++ {
		infos = append(infos, qbit.TorrentInfo{Hash: fmt.Sprintf("%040x", i), Progress: 0.1})
	}
	lister.set(infos...)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w.Track(qbit.Watched{
				InfoHash:   fmt.Sprintf("%040x", i),
				Name:       "торрент",
				TelegramID: "42",
			})
		}(i)
	}
	wg.Wait()

	waitFor(t, "несколько опросов подряд", func() bool { return lister.calls.Load() >= 5 })
	if got := lister.maxInFlight.Load(); got > 1 {
		t.Fatalf("одновременных опросов %d — значит, воркеров больше одного", got)
	}
}

// Не дошедшее сообщение — не повод ни падать, ни повторять: чаще всего это
// «bot can't initiate conversation with a user». Торрент всё равно уходит из
// хранилища, иначе воркер крутился бы вечно.
func TestWatcherDropsTorrentWhenDirectMessageFails(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{err: errors.New("bot can't initiate conversation with a user")}
	w, _ := newWatcher(t, lister, dm)

	lister.set(qbit.TorrentInfo{Hash: "aabb", Progress: 0.5})
	trackRunning(t, w, lister, watched("aabb", "42"))

	lister.set(qbit.TorrentInfo{Hash: "aabb", Progress: 1})
	waitFor(t, "воркер остановился несмотря на ошибку", func() bool { return !w.Running() })
	if got := dm.all(); len(got) != 0 {
		t.Fatalf("сообщение считается доставленным: %v", got)
	}
}

// Опрос упал — цикл обязан продолжаться: qBittorrent перезапускают, и терять
// из-за этого все отслеживаемые загрузки нельзя.
func TestWatcherSurvivesPollError(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	lister.fail(errors.New("qBittorrent недоступен"))
	w.Track(watched("aabb", "42"))
	waitFor(t, "несколько неудачных опросов", func() bool { return lister.calls.Load() >= 3 })
	if !w.Running() {
		t.Fatal("воркер сдался после ошибки опроса")
	}

	lister.set(qbit.TorrentInfo{Hash: "aabb", Progress: 1})
	waitFor(t, "сообщение после восстановления", func() bool { return len(dm.all()) == 1 })
}

// Торренты, за которыми следить нечем, в хранилище попадать не должны: без
// хеша их не сопоставить с ответом qBittorrent, без адресата — некому писать.
func TestWatcherIgnoresUntrackableTorrents(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	w.Track(
		qbit.Watched{Name: "ссылка на .torrent", TelegramID: "42"}, // хеша ещё нет
		qbit.Watched{InfoHash: "aabb", Name: "мимо портала"},       // автор неизвестен
	)

	if w.Running() {
		t.Fatal("воркер поднят ради торрентов, за которыми нечего наблюдать")
	}
	time.Sleep(20 * time.Millisecond)
	if lister.calls.Load() != 0 {
		t.Fatalf("выполнено %d опросов при пустом хранилище", lister.calls.Load())
	}
}

// Чужие торренты (RSS, папка автозагрузки, прямой доступ к qBittorrent) в
// ответе есть всегда, и сообщать о них некому.
func TestWatcherIgnoresForeignTorrents(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	lister.set(
		qbit.TorrentInfo{Hash: "eeee", Name: "чужой", Progress: 1},
		qbit.TorrentInfo{Hash: "aabb", Name: "наш", Progress: 1},
	)
	w.Track(watched("aabb", "42"))

	waitFor(t, "сообщение о своём торренте", func() bool { return len(dm.all()) == 1 })
	if got := dm.all()[0]; got != "42|наш" {
		t.Fatalf("сообщение = %q", got)
	}
}

// Хеши в ответе qBittorrent приходят в другом регистре, чем в magnet-ссылке.
// Без приведения к одному регистру совпадений не будет никогда.
func TestWatcherMatchesHashCaseInsensitively(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	lister.set(qbit.TorrentInfo{Hash: "C12FE1C0", Name: "Ubuntu", Progress: 1})
	w.Track(watched("c12fe1c0", "42"))

	waitFor(t, "совпадение по хешу в другом регистре", func() bool { return len(dm.all()) == 1 })
}

// Хранилище живёт в памяти и наполняется по запросу резидента. Без потолка
// скрипт резидента раздул бы его до десятков тысяч записей, которые воркер
// перебирал бы каждые пятнадцать секунд.
func TestWatcherCapsStore(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	const over = 50
	items := make([]qbit.Watched, 0, qbit.MaxWatchedForTest+over)
	infos := make([]qbit.TorrentInfo, 0, qbit.MaxWatchedForTest+over)
	for i := 0; i < qbit.MaxWatchedForTest+over; i++ {
		hash := fmt.Sprintf("%040x", i)
		items = append(items, qbit.Watched{
			InfoHash: hash, Name: "торрент", TelegramID: "42",
		})
		// Все они существуют в qBittorrent и качаются: тест про потолок
		// хранилища, а не про снятие наблюдения с удалённых.
		infos = append(infos, qbit.TorrentInfo{Hash: hash, Progress: 0.5})
	}
	lister.set(infos...)
	w.Track(items...)

	if got := w.Tracked(); got != qbit.MaxWatchedForTest {
		t.Fatalf("под наблюдением %d торрентов при потолке %d",
			got, qbit.MaxWatchedForTest)
	}

	// Что именно отброшено, тоже важно: сверх потолка не принимается ничего.
	// Прежняя версия теста проверяла только первый торрент и прошла бы даже
	// с полностью удалённым потолком.
	beyond := fmt.Sprintf("%040x", qbit.MaxWatchedForTest+over-1)
	first := fmt.Sprintf("%040x", 0)
	// Копия, а не правка на месте: срез уже отдан воркеру, и менять его под
	// работающей горутиной — гонка.
	done := append([]qbit.TorrentInfo(nil), infos...)
	done[len(done)-1] = qbit.TorrentInfo{Hash: beyond, Name: "лишний", Progress: 1}
	lister.set(done...)
	time.Sleep(20 * time.Millisecond)
	if got := dm.all(); len(got) != 0 {
		t.Fatalf("торрент сверх потолка всё же отслеживался: %v", got)
	}

	// А первый — принят и работает.
	done = append([]qbit.TorrentInfo(nil), done...)
	done[0] = qbit.TorrentInfo{Hash: first, Name: "первый", Progress: 1}
	lister.set(done...)
	waitFor(t, "сообщение о первом торренте", func() bool { return len(dm.all()) == 1 })
}

// Загрузка может не закончиться никогда: торрент удалили, поставили на паузу
// навсегда или добавили мёртвой ссылкой. Без срока такая запись осталась бы в
// хранилище навечно, воркер никогда бы не остановился, а потолок медленно
// заполнился бы мусором — после чего новые торренты молча перестали бы
// отслеживаться.
func TestWatcherDropsStaleDownloads(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	// Торрент есть в qBittorrent, но не завершается никогда — так выглядит
	// вечная пауза или мёртвая магнит-ссылка.
	lister.set(qbit.TorrentInfo{Hash: "aabb", Name: "фильм", Progress: 0.5})
	trackRunning(t, w, lister, watched("aabb", "42"))
	if w.Tracked() != 1 {
		t.Fatalf("под наблюдением %d торрентов", w.Tracked())
	}

	// Отматываем время вперёд: запись обязана истечь и уйти.
	w.SetClockForTest(func() time.Time { return time.Now().Add(2 * qbit.WatchTTLForTest) })

	waitFor(t, "истёкшая запись выброшена", func() bool { return w.Tracked() == 0 })
	waitFor(t, "воркер остановился", func() bool { return !w.Running() })
	if got := dm.all(); len(got) != 0 {
		t.Fatalf("по истёкшей загрузке отправлено сообщение: %v", got)
	}
}

// Остановка шлюза не должна ронять воркер посреди опроса — Serve обязан его
// дождаться, иначе горутина переживёт процесс.
func TestWatcherStopsOnShutdown(t *testing.T) {
	lister := &fakeLister{delay: 20 * time.Millisecond}
	dm := &fakeDM{}
	ctx, cancel := context.WithCancel(context.Background())
	w := qbit.NewDownloadWatcher(ctx, lister, dm, quiet(), time.Millisecond)

	trackRunning(t, w, lister, watched("aabb", "42"))

	cancel()
	stopped := make(chan struct{})
	go func() { defer close(stopped); w.Wait() }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Wait не дождался воркера после отмены")
	}
	if w.Running() {
		t.Fatal("после остановки воркер числится работающим")
	}
}

// Торрент, добавленный уже на остановке шлюза, цикл поднимать не должен:
// горутина пережила бы процесс, а сообщение всё равно не дошло бы.
func TestWatcherDoesNotStartAfterShutdown(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}

	ctx, cancel := context.WithCancel(context.Background())
	w := qbit.NewDownloadWatcher(ctx, lister, dm, quiet(), time.Millisecond)
	cancel()

	lister.set(qbit.TorrentInfo{Hash: "aabb", Name: "Ubuntu", Progress: 1})
	w.Track(watched("aabb", "42"))

	if w.Running() {
		t.Fatal("цикл запущен на отменённом контексте")
	}
	time.Sleep(20 * time.Millisecond)
	if lister.calls.Load() != 0 {
		t.Fatalf("выполнено %d опросов после остановки шлюза", lister.calls.Load())
	}
	w.Wait() // не должен зависнуть
}

// Нулевой или отрицательный интервал — не повод крутить опрос без паузы.
func TestWatcherFallsBackToDefaultInterval(t *testing.T) {
	lister := &fakeLister{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := qbit.NewDownloadWatcher(ctx, lister, &fakeDM{}, quiet(), 0)

	w.Track(watched("aabb", "42"))
	if !w.Running() {
		t.Fatal("воркер не поднялся")
	}
	// Интервал по умолчанию — пятнадцать секунд, поэтому за несколько
	// миллисекунд не должно случиться ни одного опроса.
	time.Sleep(20 * time.Millisecond)
	if got := lister.calls.Load(); got != 0 {
		t.Fatalf("выполнено %d опросов: интервал сбросился в ноль", got)
	}
}

// Без токена бота единственный результат работы воркера — личное сообщение —
// отправить некому. Опрашивать ради этого qBittorrent каждые пятнадцать
// секунд бессмысленно, поэтому воркер не поднимается вовсе.
func TestWatcherStaysDownWithoutBot(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{off: true}
	w, _ := newWatcher(t, lister, dm)

	w.Track(watched("aabb", "42"))

	if w.Running() {
		t.Fatal("воркер запущен при ненастроенном боте")
	}
	if got := w.Tracked(); got != 0 {
		t.Fatalf("под наблюдением %d торрентов, ожидался ноль", got)
	}
	// И qBittorrent при этом не опрашивается вовсе.
	time.Sleep(30 * time.Millisecond)
	if calls := lister.calls.Load(); calls != 0 {
		t.Fatalf("выполнено %d опросов qBittorrent без бота", calls)
	}
}

// Торрент, удалённый из qBittorrent, не закончится никогда: ждать его
// бессмысленно, а запись держала бы цикл опроса живым до истечения недельного
// срока.
func TestWatcherDropsDeletedTorrent(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	// Сначала торрент есть и качается.
	lister.set(qbit.TorrentInfo{Hash: "aabb", Name: "фильм", Progress: 0.5})
	trackRunning(t, w, lister, watched("aabb", "42"))

	// Затем его удаляют — из ответа qBittorrent он исчезает.
	lister.set(qbit.TorrentInfo{Hash: "ffff", Name: "чужой", Progress: 0.5})

	waitFor(t, "наблюдение снято", func() bool { return w.Tracked() == 0 })
	waitFor(t, "воркер остановился", func() bool { return !w.Running() })
	if got := dm.all(); len(got) != 0 {
		t.Fatalf("по удалённому торренту отправлено сообщение: %v", got)
	}
}

// Торрент, добавленный уже после того, как ответ qBittorrent был собран, в
// этом ответе отсутствует законно. Снимать с него наблюдение нельзя — иначе
// добавленный не вовремя торрент терялся бы молча.
func TestWatcherKeepsTorrentAddedDuringPoll(t *testing.T) {
	lister := &fakeLister{}
	dm := &fakeDM{}
	w, _ := newWatcher(t, lister, dm)

	// В qBittorrent есть посторонний торрент — только чтобы поднялся цикл и
	// ответ не был пустым.
	lister.set(qbit.TorrentInfo{Hash: "ffff", Name: "чужой", Progress: 0.5})
	trackRunning(t, w, lister, watched("ffff", "1"))

	// Свежий торрент, которого в ответах ещё не было ни разу.
	w.Track(watched("aabb", "42"))

	// Он появляется в следующем же ответе — как и бывает на самом деле.
	lister.set(
		qbit.TorrentInfo{Hash: "ffff", Name: "чужой", Progress: 0.5},
		qbit.TorrentInfo{Hash: "aabb", Name: "фильм", Progress: 0.5},
	)
	time.Sleep(60 * time.Millisecond)
	if w.Tracked() < 2 {
		t.Fatalf("торрент снят с наблюдения из-за одного промаха, осталось %d", w.Tracked())
	}

	// И когда он закончится — сообщение придёт.
	lister.set(
		qbit.TorrentInfo{Hash: "ffff", Name: "чужой", Progress: 0.5},
		qbit.TorrentInfo{Hash: "aabb", Name: "фильм", Progress: 1},
	)
	waitFor(t, "сообщение о загрузке", func() bool {
		for _, s := range dm.all() {
			if s == "42|фильм" {
				return true
			}
		}
		return false
	})
}
