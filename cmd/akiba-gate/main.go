// akiba-gate — единая точка входа в сервисы резидентов Akiba.
//
// Что делает сервис:
//   - /verify — эндпоинт ForwardAuth для Traefik: проверяет JWT, выданный
//     внешним auth-service, и решает, пускать ли запрос дальше;
//   - / — портал со ссылками, которые видны только тем, кому сервис разрешён;
//   - /sso/jellyfin — автовход в Jellyfin через быстрое подключение;
//   - /jellyfin/* — сам Jellyfin: на origin портала, иначе автовход невозможен;
//   - /qbittorrent/* — прокси к qBittorrent: сообщает в чат о добавленных
//     торрентах и пишет автору в личку, когда загрузка закончилась;
//   - /nextcloud — вход в Nextcloud одноразовым кодом, без пароля;
//   - /nextcloud/redeem — обмен кода на личность приложением внутри Nextcloud;
//   - /admin — управление резидентами: кому какие сервисы доступны;
//   - /userpic/* — аватарки Telegram через шлюз; включается вместе с SOCKS5,
//     без прокси портал ссылается на t.me напрямую;
//   - /trrntlink — переход на магнит-ссылку из сообщения бота.
//
// Приватный ключ подписи токенов сервису не нужен и никогда не передаётся:
// достаточно публичного ключа auth-service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/akiba-hs/akiba-gate/internal/access"
	"github.com/akiba-hs/akiba-gate/internal/admin"
	"github.com/akiba-hs/akiba-gate/internal/app"
	"github.com/akiba-hs/akiba-gate/internal/audit"
	"github.com/akiba-hs/akiba-gate/internal/auth"
	"github.com/akiba-hs/akiba-gate/internal/config"
	"github.com/akiba-hs/akiba-gate/internal/directory"
	"github.com/akiba-hs/akiba-gate/internal/i18n"
	"github.com/akiba-hs/akiba-gate/internal/jellyfin"
	"github.com/akiba-hs/akiba-gate/internal/nextcloud"
	"github.com/akiba-hs/akiba-gate/internal/portal"
	"github.com/akiba-hs/akiba-gate/internal/qbit"
	"github.com/akiba-hs/akiba-gate/internal/socks5"
	"github.com/akiba-hs/akiba-gate/internal/tgnotify"
	"github.com/akiba-hs/akiba-gate/internal/userpic"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "akiba-gate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)

	texts, err := i18n.Load(cfg.I18nPath, cfg.I18nTTL, log)
	if err != nil {
		return err
	}
	log.Info("тексты интерфейса загружены", "path", cfg.I18nPath, "cache_ttl", cfg.I18nTTL.String())

	verifier, err := auth.NewVerifier(cfg.JWTPublicKeyPEM)
	if err != nil {
		return err
	}
	store, err := audit.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	// Клиент общего назначения: следует за редиректами, годится для API.
	apiClient := &http.Client{Timeout: cfg.Timeout}
	// Клиент для форм входа: редиректы нужны нам как результат, а не как
	// действие, иначе cookie сессии потеряются по дороге.
	noRedirect := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	tgClient := newTelegramClient(cfg, log)

	// Единая политика имён хостов: по ней проверяются и адрес возврата после
	// входа, и адрес, который уходит в localStorage браузера.
	allowedHosts := append([]string{}, cfg.ExtraHosts...)
	hosts := auth.HostPolicy{Base: cfg.PublicBaseURL, Allowed: allowedHosts}

	// Адрес возврата подставляем, только когда он отличается от публичного.
	var returnBase *url.URL
	if cfg.AuthReturnBaseURL != nil && cfg.AuthReturnBaseURL.Host != cfg.PublicBaseURL.Host {
		returnBase = cfg.AuthReturnBaseURL
		// Разница по громкости не случайна. Возврат на другое наше имя —
		// рабочая настройка: человек всё равно попадает на портал, просто
		// по адресу без порта, который принимает auth-service. А возврат на
		// чужой хост (например, на страницу самого auth-service) оставляет
		// его на постороннем сайте, и портал вынужден ловить вход опросом.
		if hosts.Allows(returnBase.Host) {
			log.Info("после входа auth-service вернёт на другое имя портала",
				"return_url", auth.ReturnTarget(returnBase),
				"portal", cfg.PublicBaseURL.String())
		} else {
			log.Warn("адрес возврата после входа ведёт не на портал: "+
				"человек останется на чужой странице, а портал дождётся входа опросом",
				"return_url", auth.ReturnTarget(returnBase),
				"portal", cfg.PublicBaseURL.String())
		}
	}

	forwardAuth := &auth.ForwardAuth{
		Verifier:        verifier,
		CookieName:      cfg.CookieName,
		AuthURL:         cfg.AuthURL,
		PublicBaseURL:   cfg.PublicBaseURL,
		AllowedHosts:    hosts.Allowed,
		ReturnBase:      returnBase,
		RequireResident: cfg.RequireResident,
		RootAdmin:       cfg.AdminTelegramID,
		Log:             log,
	}

	// Права доступа персональные и лежат в базе. Умолчание — «ничего»:
	// новый резидент видит пустой портал, пока администратор не откроет ему
	// сервисы. Сам администратор задан конфигурацией, и его доступ не зависит
	// от базы вовсе — иначе одна неверная галочка заперла бы систему.
	policy := access.StorePolicy{Grants: store, RootAdmin: cfg.AdminTelegramID}
	catalog := access.Catalog{
		JellyfinURL:  "/sso/jellyfin",
		QbitURL:      cfg.QbitBasePath + "/",
		NextcloudURL: nextcloud.OpenPath,
		AdminURL:     admin.Path,
	}

	notifier := tgnotify.New(tgnotify.Config{
		Token:   cfg.TelegramToken,
		ChatID:  cfg.TelegramChatID,
		BaseURL: cfg.PublicBaseURL.String(),
		HTTP:    tgClient,
	}, torrentMessages{texts}, log)

	// Контекст жизни процесса нужен уже здесь: воркер загрузок получает его
	// при создании, чтобы торрент, добавленный сразу после старта, не попал
	// в окно «хранилище уже принимает, цикл ещё не поднимается».
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Список резидентов: пополняется входами, чистится сверкой с чатом.
	residents := directory.NewRecorder(store, log)
	reconciler := directory.NewReconciler(store, notifier, residents,
		[]string{cfg.AdminTelegramID}, log)

	jellyfinClient := jellyfin.NewClient(cfg.JellyfinInternalURL, apiClient,
		cfg.JellyfinUser, cfg.JellyfinPassword)
	qbitClient := qbit.NewClient(cfg.QbitInternalURL, noRedirect, cfg.QbitUser, cfg.QbitPassword,
		cfg.QbitAuthMode == config.QbitAuthSession)
	// Воркер загрузок: следит за торрентами, добавленными через портал, и
	// пишет их авторам в личку, когда загрузка закончилась. Своей горутины
	// на простое у него нет — она появляется на первом добавлении.
	downloads := qbit.NewDownloadWatcher(ctx, qbitClient, notifier, log, qbit.DefaultPollInterval)
	qbitProxy := qbit.NewProxy(cfg.QbitBasePath, cfg.QbitInternalURL, qbitClient,
		downloads, notifier, hosts, log)

	// Одноразовые коды входа в Nextcloud живут в памяти: они действуют
	// минуту, и переживать перезапуск им незачем.
	ssoCodes := nextcloud.NewCodes()
	// Кука с nonce привязывает код к браузеру, который его запросил. Она
	// обязана доехать до соседнего имени, поэтому ставится на общий домен
	// портала и Nextcloud. Общего домена может не быть — например, при
	// локальной отладке Nextcloud адресуют по IP; тогда привязки не будет, и
	// об этом надо сказать вслух, а не молча ослабить защиту.
	nonceDomain := nextcloud.NonceDomain(cfg.PublicBaseURL.Host, cfg.NextcloudPublicURL.Host)
	if nonceDomain == "" {
		log.Warn("у портала и Nextcloud нет общего домена: одноразовый код "+
			"не будет привязан к браузеру, останется только привязка по адресу",
			"portal", cfg.PublicBaseURL.Host, "nextcloud", cfg.NextcloudPublicURL.Host)
	}
	log.Info("вход в Nextcloud настроен",
		"nextcloud", cfg.NextcloudPublicURL.String(),
		"sso_path", cfg.NextcloudSSOPath, "bind_ip", cfg.NextcloudSSOBindIP,
		"nonce_domain", nonceDomain)
	log.Info("администратор из конфигурации", "user", "tg"+cfg.AdminTelegramID)

	// Один ограничитель на оба пути подтверждения кода: код быстрого
	// подключения — шесть цифр, и без него их можно перебирать скриптом.
	quickConnectAttempts := jellyfin.NewAttemptLimiter()

	router := app.NewRouter(app.Deps{
		Log:         log,
		ForwardAuth: forwardAuth,
		Policy:      policy,
		Portal: &portal.Handler{
			Verifier:   verifier,
			CookieName: cfg.CookieName,
			AuthURL:    cfg.AuthURL,
			Hosts:      hosts,
			Policy:     policy,
			Catalog:    catalog,
			Texts:      texts,
			ReturnBase: returnBase,
			// Через шлюз аватарки идут только при заданном SOCKS5: ради
			// этого случая прослойка и написана. См. portal.Handler.
			ProxyUserPics: cfg.SocksAddress != "",
			Audience:      auth.NewSeen(),
			Residents:     residents,
			Log:           log,
		},
		JellyfinSSO: &jellyfin.SSOHandler{
			BasePath: cfg.JellyfinBasePath,
			Hosts:    hosts,
			Log:      log,
		},
		// Прокси Jellyfin намеренно не использует apiClient: его таймаут
		// в 15 секунд оборвал бы просмотр видео на первой же паузе буфера.
		JellyfinProxy:    jellyfin.NewProxy(cfg.JellyfinBasePath, cfg.JellyfinInternalURL, log),
		JellyfinBasePath: cfg.JellyfinBasePath,
		JellyfinConnect: &jellyfin.QuickConnectHandler{
			Client:   jellyfinClient,
			BasePath: cfg.JellyfinBasePath,
			Hosts:    hosts,
			Attempts: quickConnectAttempts,
			Log:      log,
		},
		JellyfinApprove: &jellyfin.QuickConnectAPI{
			Client:   jellyfinClient,
			Hosts:    hosts,
			Attempts: quickConnectAttempts,
			Log:      log,
		},
		QbitProxy:    qbitProxy,
		QbitBasePath: cfg.QbitBasePath,
		NextcloudOpen: &nextcloud.OpenHandler{
			Target: nextcloud.StartPath,
			Log:    log,
		},
		NextcloudSSO: &nextcloud.StartHandler{
			Codes:        ssoCodes,
			PublicURL:    cfg.NextcloudPublicURL,
			SSOPath:      cfg.NextcloudSSOPath,
			BindIP:       cfg.NextcloudSSOBindIP,
			CookieDomain: nonceDomain,
			Log:          log,
		},
		NextcloudRedeem: &nextcloud.RedeemHandler{
			Codes:  ssoCodes,
			Secret: cfg.NextcloudSSOSecret,
			Log:    log,
		},
		Admin: &admin.Handler{
			Store:     store,
			Texts:     texts,
			Catalog:   catalog,
			Hosts:     hosts,
			RootAdmin: cfg.AdminTelegramID,
			Reconcile: reconciler,
			Log:       log,
		},
		Residents:   residents,
		UserPic:     userpic.Handler{HTTP: tgClient, Log: log},
		TorrentLink: tgnotify.LinkHandler{Log: log},
	})

	// Фоновых задач две, и обе обязаны закончиться до закрытия базы.
	//
	// Воркер загрузок: своей горутины на простое у него нет — она появляется
	// на первом добавленном торренте и исчезает, когда все загрузки
	// закончились. Ждём её, чтобы не оборвать отправку сообщения в чат.
	//
	// Сверка состава чата: запускается с открытия админки и пишет в базу.
	// Без ожидания она попадала бы на уже закрытое соединение и удаляла
	// выбывших наполовину.
	var background sync.WaitGroup
	background.Add(1)
	go func() {
		defer background.Done()
		<-ctx.Done()
		downloads.Wait()
		reconciler.Wait()
	}()
	// Ждать фоновые задачи через defer нельзя: он сработал бы раньше
	// отложенного stop(), контекст остался бы неотменённым, и на аварийном
	// выходе (например, занятый порт) процесс завис бы навсегда.
	shutdown := func() {
		stop()
		background.Wait()
	}

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: router,
		// Заголовки читаем быстро, тело — сколько нужно: через прокси идут
		// загрузки .torrent и потоковое видео Jellyfin.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// BaseContext намеренно не привязан к контексту сигналов: иначе
		// SIGTERM отменял бы контекст уже выполняющихся запросов, и Shutdown
		// ждал бы обрывки вместо корректно завершённых обработчиков.
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("akiba-gate запущен", "listen_addr", cfg.ListenAddr, "portal", cfg.PublicBaseURL.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		shutdown()
		return err
	case <-ctx.Done():
		log.Info("получен сигнал остановки, завершаемся")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	shutdown()
	return err
}

// newTelegramClient собирает единственного клиента для всего Telegram.
//
// Один на всё: и аватарки с t.me, и сообщения бота на api.telegram.org.
// Отдельных клиентов намеренно нет — прокси в конфигурации один на весь
// Telegram, и разводить их значило бы однажды завести новый выход наружу и
// забыть прокинуть в него SOCKS5.
func newTelegramClient(cfg *config.Config, log *slog.Logger) *http.Client {
	c := &http.Client{Timeout: cfg.Timeout}
	if cfg.SocksAddress == "" {
		log.Info("SOCKS5 не задан: в Telegram ходим напрямую")
		return c
	}
	dialer := &socks5.Dialer{
		Address: cfg.SocksAddress, User: cfg.SocksUser, Password: cfg.SocksPassword,
	}
	// Присваиваем только непустой транспорт: nil-указатель в поле интерфейса
	// даёт не «поведение по умолчанию», а панику на первом запросе.
	if tr := socks5.Transport(dialer); tr != nil {
		c.Transport = tr
	}
	log.Info("запросы в Telegram пойдут через SOCKS5", "proxy", cfg.SocksAddress)
	return c
}

// torrentMessages отдаёт боту шаблон сообщения, перечитывая файл переводов.
// Отдельный тип, а не метод у Bundle: пакету уведомлений незачем знать про
// весь словарь, ему нужна одна строка.
type torrentMessages struct{ texts *i18n.Bundle }

func (t torrentMessages) TorrentAdded() string { return t.texts.Messages().TorrentAdded }

func (t torrentMessages) TorrentDownloaded() string {
	return t.texts.Messages().TorrentDownloaded
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
