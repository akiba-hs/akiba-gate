<?php

declare(strict_types=1);

namespace OCA\AkibaSso\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\Files\IRootFolder;
use OCP\IGroupManager;
use OCP\Http\Client\IClientService;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Security\ISecureRandom;
use Psr\Log\LoggerInterface;

/**
 * Адаптер между akiba-gate и Nextcloud.
 *
 * Вся его работа — четыре шага: получить код из адреса, обменять его у шлюза
 * на личность, завести резидента, если такого ещё нет, и открыть ему
 * сессию средствами самого Nextcloud.
 *
 * Чего здесь намеренно нет — пароля как механизма входа. При создании
 * учётной записи Nextcloud требует какой-нибудь пароль, поэтому мы генерируем
 * случайный и тут же его забываем: он никуда не сохраняется и никогда не
 * используется для входа. Человек волен задать себе собственный пароль и
 * менять его когда угодно — вход по коду от этого не зависит вовсе.
 */
class SsoController extends Controller {
    private const APP_ID = 'akibasso';

    /** Сколько ждём ответа шлюза. Он рядом, в той же сети. */
    private const TIMEOUT = 10;

    /** Кука с nonce, которую поставил шлюз. Имя совпадает с его константой. */
    private const NONCE_COOKIE = 'akiba_nc_sso';

    /** Группа, в которую попадают заведённые резиденты. */
    private const RESIDENTS_GROUP = 'residents';

    public function __construct(
        string $appName,
        IRequest $request,
        private IUserManager $userManager,
        private IGroupManager $groupManager,
        private IUserSession $userSession,
        private ISession $session,
        private IConfig $config,
        private IRootFolder $rootFolder,
        private IClientService $clientService,
        private ISecureRandom $random,
        private LoggerInterface $logger,
    ) {
        parent::__construct($appName, $request);
    }

    /**
     * Вход по одноразовому коду.
     *
     * Атрибуты, а не докблок-аннотации: аннотации в Nextcloud объявлены
     * устаревшими и однажды перестанут учитываться. Отказ был бы тихим —
     * маршрут начал бы требовать вход, и SSO сломалось бы на обновлении.
     */
    #[PublicPage]
    #[NoCSRFRequired]
    #[UseSession]
    public function login(string $code = ''): RedirectResponse|TemplateResponse {
        if ($code === '') {
            return $this->fail('Код входа не передан.');
        }

        $identity = $this->redeem($code);
        if ($identity === null) {
            return $this->fail('Код входа недействителен или истёк. Вернитесь на портал и нажмите на Nextcloud ещё раз.');
        }

        $user = $this->userManager->get($identity['uid']);
        if ($user === null) {
            $user = $this->provision($identity['uid'], $identity['display_name']);
            if ($user === null) {
                return $this->fail('Не удалось создать аккаунт. Сообщите администратору.');
            }
        } else {
            $this->syncDisplayName($user, $identity['display_name']);
        }

        if (!$this->completeLogin($user)) {
            return $this->fail('Не удалось открыть сессию. Сообщите администратору.');
        }

        $this->prepareFilesystem($user);

        return new RedirectResponse(\OC::$WEBROOT . $this->landingPath());
    }

    /**
     * Куда отправить человека после входа.
     *
     * Значение приходит из настройки, то есть от администратора Nextcloud, —
     * но проверить его всё равно нужно: "//evil.example" браузер поймёт как
     * протокольно-относительный адрес и уйдёт на чужой сайт. Одна строка
     * проверки дешевле, чем открытый редирект.
     */
    private function landingPath(): string {
        $landing = $this->config->getAppValue(self::APP_ID, 'landing_path', '/apps/files');
        if (!str_starts_with($landing, '/') || str_starts_with($landing, '//')) {
            $this->logger->warning('akibasso: некорректный landing_path, беру /apps/files');
            return '/apps/files';
        }
        return $landing;
    }

    /**
     * Обменивает код на личность у шлюза.
     *
     * Запрос идёт от сервера к серверу и подписан общим секретом: украденный
     * код без него бесполезен.
     *
     * Вместе с кодом пересылаем nonce из куки, которую шлюз поставил тому же
     * браузеру. Это и есть привязка к flow: без неё резидент мог бы получить
     * код на свой аккаунт и заставить чужой браузер открыть ссылку с ним —
     * жертва молча оказалась бы в его Nextcloud.
     *
     * Адрес браузера — вторая, более слабая проверка. Чтобы он был настоящим,
     * а не адресом Traefik, в config.php Nextcloud должен быть прописан
     * trusted_proxies (см. README приложения).
     *
     * @return array{uid: string, display_name: string}|null
     */
    private function redeem(string $code): ?array {
        $gate = rtrim($this->config->getAppValue(self::APP_ID, 'gate_url', ''), '/');
        $secret = $this->config->getAppValue(self::APP_ID, 'shared_secret', '');
        if ($gate === '' || $secret === '') {
            $this->logger->error('akibasso: не настроены gate_url или shared_secret');
            return null;
        }

        try {
            $response = $this->clientService->newClient()->post($gate . '/nextcloud/redeem', [
                'headers' => [
                    'X-Akiba-SSO-Secret' => $secret,
                    'Content-Type' => 'application/json',
                ],
                'body' => json_encode([
                    'code' => $code,
                    'nonce' => $this->request->getCookie(self::NONCE_COOKIE) ?? '',
                    'client_ip' => $this->request->getRemoteAddress(),
                ], JSON_THROW_ON_ERROR),
                'timeout' => self::TIMEOUT,
                // Шлюз живёт в локальной сети, а Nextcloud по умолчанию
                // запрещает своим серверным запросам ходить на частные
                // адреса — это защита от SSRF, и она обязана оставаться
                // включённой для всего остального. Здесь адрес приходит не
                // от посетителя, а из настройки gate_url, которую задаёт
                // администратор, поэтому исключение делается ровно для
                // этого запроса. Без него обмен падает всегда и с внятной
                // записью в журнале: «violates local access rules».
                //
                // Альтернатива — системная настройка
                // allow_local_remote_servers, — снимает запрет со всего
                // Nextcloud разом (федерация, внешние хранилища), поэтому
                // она здесь не годится.
                'nextcloud' => ['allow_local_address' => true],
            ]);
        } catch (\Throwable $e) {
            // Причину пишем в журнал, но наружу не отдаём: она различает
            // «код не тот» и «код с чужого адреса», а это подсказка атакующему.
            $this->logger->warning('akibasso: обмен кода не удался: ' . $e->getMessage());
            return null;
        }

        $body = json_decode((string)$response->getBody(), true);
        if (!is_array($body) || !isset($body['uid']) || $body['uid'] === '') {
            $this->logger->warning('akibasso: шлюз вернул ответ без uid');
            return null;
        }
        return [
            'uid' => (string)$body['uid'],
            'display_name' => (string)($body['display_name'] ?? $body['uid']),
        ];
    }

    /**
     * Заводит учётную запись резидента.
     *
     * Пароль случайный и одноразовый: он нужен только потому, что Nextcloud
     * не умеет создавать учётную запись без него. Никуда не сохраняется и для
     * входа не используется — вход идёт по коду от шлюза.
     */
    private function provision(string $uid, string $displayName): ?IUser {
        $throwaway = $this->random->generate(64, ISecureRandom::CHAR_ALPHANUMERIC);
        try {
            $user = $this->userManager->createUser($uid, $throwaway);
        } catch (\Throwable $e) {
            $this->logger->error('akibasso: не удалось создать резидента ' . $uid . ': ' . $e->getMessage());
            return null;
        }
        if ($user === false) {
            $this->logger->error('akibasso: не удалось создать резидента ' . $uid);
            return null;
        }
        if ($displayName !== '') {
            $user->setDisplayName($displayName);
        }
        $this->addToResidentsGroup($user);
        $this->logger->info('akibasso: создан резидент ' . $uid);
        return $user;
    }

    /**
     * Кладёт резидента в общую группу.
     *
     * Группа нужна, чтобы права и общие папки выдавались один раз на всех, а
     * не каждому заведённому аккаунту вручную. Имя группы настраивается:
     * `occ config:app:set akibasso residents_group --value=…`. Пустое
     * значение отключает раскладку по группам целиком.
     *
     * Отказ здесь не срывает вход: человек уже опознан, и оставить его снаружи
     * из-за группы — хуже, чем впустить без неё. Поэтому только запись в
     * журнал, по которой администратор увидит расхождение.
     */
    private function addToResidentsGroup(IUser $user): void {
        $name = $this->config->getAppValue(self::APP_ID, 'residents_group', self::RESIDENTS_GROUP);
        if ($name === '') {
            return;
        }
        try {
            $group = $this->groupManager->get($name);
            if ($group === null) {
                $group = $this->groupManager->createGroup($name);
            }
            if ($group === null) {
                $this->logger->warning('akibasso: не удалось создать группу ' . $name);
                return;
            }
            if (!$group->inGroup($user)) {
                $group->addUser($user);
            }
        } catch (\Throwable $e) {
            $this->logger->warning('akibasso: не удалось добавить '
                . $user->getUID() . ' в группу ' . $name . ': ' . $e->getMessage());
        }
    }

    /**
     * Открывает резиденту сессию.
     *
     * Именно так это делают штатные SSO-приложения Nextcloud: сессия
     * создаётся ядром, со всеми его проверками и токенами, а пароль при этом
     * не участвует.
     */
    private function completeLogin(IUser $user): bool {
        try {
            // Регенерация идентификатора сессии обязательна: без неё
            // идентификатор, известный до входа, остался бы действительным
            // и после — это классическая фиксация сессии.
            $this->session->regenerateId();
            $this->userSession->setUser($user);
            $this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());
            // createRememberMeToken здесь намеренно НЕ вызывается. Он выдал бы
            // постоянную куку на две недели, и человек, у которого админ
            // только что отобрал доступ, сохранял бы вход всё это время.
            // Заново войти — одно нажатие на карточку портала.
        } catch (\Throwable $e) {
            $this->logger->error('akibasso: не удалось открыть сессию для ' . $user->getUID() . ': ' . $e->getMessage());
            return false;
        }
        return true;
    }

    /**
     * Держит имя в Nextcloud тем же, что и в Telegram.
     *
     * Источник истины — Telegram: имя приходит в каждом обмене кода. Плата
     * за это — имя, выставленное самим человеком в настройках Nextcloud,
     * заменяется при следующем входе; размен осознанный, чтобы резидента
     * узнавали по одному имени во всех сервисах.
     */
    private function syncDisplayName(IUser $user, string $displayName): void {
        if ($displayName === '' || $user->getDisplayName() === $displayName) {
            return;
        }
        if (!$user->setDisplayName($displayName)) {
            $this->logger->warning('akibasso: не удалось обновить имя для ' . $user->getUID());
            return;
        }
        $this->logger->info('akibasso: имя резидента ' . $user->getUID() . ' обновлено из Telegram');
    }

    /**
     * Готовит файловое хранилище резидента.
     *
     * Обычный вход в Nextcloud делает это сам, в Session::prepareUserLogin():
     * настраивает файловую систему, создаёт каталог `<uid>/files` и копирует
     * туда «скелет» — приветственные файлы. Наш вход идёт мимо этого пути, и
     * без такой подготовки учётная запись остаётся без корня файлов: сессия
     * открывается, человек попадает внутрь, а «Файлы» отвечают 500 и пишут в
     * журнал `The root directory of the user's files is missing`. Снаружи это
     * выглядит как «вход сломан», хотя вход как раз отработал.
     *
     * Признак первого входа берём у самого Nextcloud: updateLastLoginTimestamp()
     * возвращает true ровно один раз. Скелет копируем только тогда — иначе
     * приветственные файлы возвращались бы после каждого входа. Каталог же
     * создаём всегда: это дёшево, идемпотентно и чинит записи, заведённые
     * прежней версией приложения, без ручного вмешательства.
     *
     * OC_Util — внутренний класс ядра, и это осознанно: публичного способа
     * настроить файловую систему за пользователя в API нет, а само ядро в
     * Session::prepareUserLogin() зовёт ровно эти две функции.
     */
    private function prepareFilesystem(IUser $user): void {
        $uid = $user->getUID();
        $firstLogin = $user->updateLastLoginTimestamp();
        try {
            \OC_Util::setupFS($uid);
            $folder = $this->rootFolder->getUserFolder($uid);
            if ($firstLogin) {
                \OC_Util::copySkeleton($uid, $folder);
            }
        } catch (\Throwable $e) {
            // Вход не отменяем: сессия уже открыта, и без скелета Nextcloud
            // работоспособен. Но в журнале это обязано остаться — иначе
            // «Файлы» отвалятся молча.
            $this->logger->warning('akibasso: не удалось подготовить файлы для ' . $uid . ': ' . $e->getMessage());
        }
    }

    private function fail(string $message): TemplateResponse {
        $response = new TemplateResponse(self::APP_ID, 'error', ['message' => $message], 'guest');
        $response->setStatus(403);
        return $response;
    }
}
