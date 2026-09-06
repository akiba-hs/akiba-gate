package jellyfin

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/akiba-hs/akiba-gate/internal/auth"
)

// SSOHandler отдаёт страницу, которая заводит резиденту сессию Jellyfin и
// уводит в веб-интерфейс.
//
// Вход делается «быстрым подключением» Jellyfin, и целиком из браузера:
// страница сама вызывает /QuickConnect/Initiate, отдаёт полученный код шлюзу
// на подтверждение и сама же обменивает секрет на токен. Шлюзу остаётся
// единственное действие, которое браузер выполнить не может, — подтвердить
// код служебной учёткой.
//
// Почему так, а не логин служебной учёткой на стороне шлюза. Токен в этом
// случае выпускается на устройство самого браузера: DeviceId тот же, что
// использует веб-клиент Jellyfin, поэтому сессия ничем не отличается от
// заведённой вручную. Работает это только потому, что портал и Jellyfin
// живут на одном origin — иначе ни запрос к API, ни запись в localStorage
// были бы невозможны.
type SSOHandler struct {
	BasePath string // публичный префикс Jellyfin, например "/jellyfin"
	// Hosts не даёт записать в localStorage адрес чужого сервера: по нему
	// веб-клиент Jellyfin ходит с полученным токеном, и подменённый Host
	// отправил бы и запросы, и токен на хост злоумышленника.
	Hosts auth.HostPolicy
	Log   *slog.Logger
}

func (h *SSOHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin, ok := h.Hosts.Origin(r)
	if !ok {
		h.Log.Warn("запрос автовхода в Jellyfin с постороннего хоста",
			"host", auth.RequestHost(r))
	}

	// Сам токен через шлюз не проходит — его получает браузер, — но
	// страница выдаёт доступ и персональна: ни кэшировать её, ни
	// индексировать нельзя.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Referrer-Policy", "no-referrer")
	auth.OwnPageHeaders(w.Header())

	data := struct {
		BasePath    string
		ServerURL   string
		ApprovePath string
		Target      string
	}{
		BasePath:    h.BasePath,
		ServerURL:   origin + h.BasePath,
		ApprovePath: QuickConnectApprovePath,
		Target:      h.BasePath + "/web/",
	}
	if err := ssoTemplate.Execute(w, data); err != nil {
		h.Log.Error("не удалось отрендерить страницу входа в Jellyfin", "error", err)
	}
}

// ssoTemplate — страница-перемычка с индикатором хода дела.
//
// Шагов четыре, и каждый может занять секунду-другую, поэтому пустой экран
// здесь недопустим: человек решит, что всё повисло, и нажмёт «назад» ровно
// посередине выдачи сессии.
var ssoTemplate = template.Must(template.New("jellyfin-sso").Parse(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вход в Jellyfin…</title>
<meta name="robots" content="noindex, nofollow">
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; background:#16181d; color:#e8e6e3;
         font:16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
         display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { width:100%; max-width:420px; text-align:center; }
  .ring { width:76px; height:76px; margin:0 auto 26px; position:relative; }
  .ring i { position:absolute; inset:0; border-radius:50%;
            border:3px solid transparent; border-top-color:#b9293b;
            animation:spin 1.1s cubic-bezier(.6,.15,.35,.85) infinite; }
  .ring i:nth-child(2) { inset:11px; border-top-color:#e8a0ab; animation-duration:1.5s;
                         animation-direction:reverse; }
  .ring i:nth-child(3) { inset:22px; border-top-color:#6c7a8f;
                         animation-duration:1.9s; }
  @keyframes spin { to { transform:rotate(360deg); } }
  h1 { font-size:1.15rem; font-weight:600; margin:0 0 8px; }
  .step { color:#9aa0ab; min-height:1.5em; transition:opacity .2s; }
  .bar { height:3px; margin:22px auto 0; max-width:260px; background:#262a33;
         border-radius:3px; overflow:hidden; }
  .bar span { display:block; height:100%; width:0; background:#b9293b;
              border-radius:3px; transition:width .45s ease; }
  .err { display:none; text-align:left; background:#3a1f24; border:1px solid #b9293b;
         border-radius:12px; padding:16px; margin-top:22px; }
  .err a { color:#e8a0ab; }
  .hidden { display:none; }
  @media (prefers-reduced-motion: reduce) {
    .ring i { animation:none; border-color:#3a4150; border-top-color:#b9293b; }
    .bar span { transition:none; }
  }
</style>
</head>
<body>
<main class="card">
  <div class="ring" id="ring" aria-hidden="true"><i></i><i></i><i></i></div>
  <h1 id="title">Открываем Jellyfin</h1>
  <p class="step" id="step">Проверяем сохранённый вход…</p>
  <div class="bar" id="bar"><span id="fill"></span></div>

  <div class="err" id="err">
    <p id="errText" style="margin:0"></p>
  </div>
</main>

<script>
(function () {
  var base = {{.BasePath}};
  var serverURL = {{.ServerURL}};
  var approvePath = {{.ApprovePath}};
  var target = {{.Target}};

  var stepEl = document.getElementById('step');
  var fillEl = document.getElementById('fill');
  function step(text, percent) {
    stepEl.textContent = text;
    fillEl.style.width = percent + '%';
  }
  function fail(text) {
    document.getElementById('ring').classList.add('hidden');
    document.getElementById('bar').classList.add('hidden');
    document.getElementById('title').textContent = 'Не получилось войти';
    stepEl.textContent = '';
    document.getElementById('errText').textContent = text;
    document.getElementById('err').style.display = 'block';
  }

  // Идентификатор устройства переиспользуем: иначе каждый вход заводил бы в
  // Jellyfin новое устройство и засорял список сессий. Формат тот же, что у
  // веб-клиента Jellyfin, — он хранит его под этим же ключом.
  function deviceId() {
    try {
      var saved = localStorage.getItem('_deviceId2');
      if (saved) return saved;
      var fresh = btoa(navigator.userAgent + '|' + Date.now())
        .replace(/=+$/, '');
      localStorage.setItem('_deviceId2', fresh);
      return fresh;
    } catch (e) {
      return 'akiba-' + Date.now();
    }
  }

  var device = deviceId();
  var version = '10.11.11';

  function authHeader(token) {
    var h = 'MediaBrowser Client="Jellyfin Web", Device="Browser", DeviceId="'
      + device + '", Version="' + version + '"';
    if (token) h += ', Token="' + token + '"';
    return h;
  }

  // Ни один запрос не должен висеть бесконечно: зависший Jellyfin оставил бы
  // человека наедине с крутящимся кольцом и без единого слова о том, что
  // случилось. Двадцати секунд хватает самому медленному ответу, а дальше
  // честнее показать ошибку.
  var REQUEST_TIMEOUT = 20000;

  function withTimeout(url, init) {
    if (typeof AbortController !== 'function') return fetch(url, init);
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, REQUEST_TIMEOUT);
    init.signal = ctrl.signal;
    return fetch(url, init).then(function (r) {
      clearTimeout(timer);
      return r;
    }, function (e) {
      clearTimeout(timer);
      throw new Error('Jellyfin не ответил вовремя.');
    });
  }

  function api(path, opts) {
    opts = opts || {};
    var headers = { 'Authorization': authHeader(opts.token) };
    if (opts.json) headers['Content-Type'] = 'application/json';
    return withTimeout(base + path, {
      method: opts.method || 'GET',
      headers: headers,
      credentials: 'same-origin',
      body: opts.json ? JSON.stringify(opts.json) : undefined
    });
  }

  function save(result) {
    var creds = { Servers: [{
      Id: result.ServerId,
      Name: 'Jellyfin',
      AccessToken: result.AccessToken,
      UserId: result.User && result.User.Id,
      ManualAddress: serverURL,
      LastConnectionMode: 2,
      DateLastAccessed: Date.now()
    }] };
    localStorage.setItem('jellyfin_credentials', JSON.stringify(creds));
    localStorage.setItem('enableAutoLogin', 'true');
  }

  function done() {
    step('Готово, открываем медиатеку…', 100);
    location.replace(target);
  }

  // Быстрый путь: рабочая сессия уже сохранена — второй раз её выдавать незачем.
  function tryExisting() {
    var raw;
    try { raw = localStorage.getItem('jellyfin_credentials'); } catch (e) { return Promise.resolve(false); }
    if (!raw) return Promise.resolve(false);
    var token;
    try {
      var servers = (JSON.parse(raw) || {}).Servers || [];
      token = servers.length && servers[0].AccessToken;
    } catch (e) { return Promise.resolve(false); }
    if (!token) return Promise.resolve(false);
    return api('/Users/Me', { token: token })
      .then(function (r) { return r.ok; })
      .catch(function () { return false; });
  }

  // Приводим версию клиента к версии сервера: Jellyfin пишет её в список
  // устройств, и расхождение там только путает администратора.
  function readVersion() {
    return api('/System/Info/Public')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (info) { if (info && info.Version) version = info.Version; })
      .catch(function () {});
  }

  function initiate() {
    step('Запрашиваем доступ у Jellyfin…', 45);
    return api('/QuickConnect/Initiate', { method: 'POST' }).then(function (r) {
      if (!r.ok) throw new Error('Jellyfin не выдал код быстрого подключения.');
      return r.json();
    });
  }

  function approve(code) {
    step('Подтверждаем доступ…', 70);
    return withTimeout(approvePath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ code: code })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok || !body.ok) {
          throw new Error(body.error || 'Шлюз не смог подтвердить код.');
        }
      });
    });
  }

  function exchange(secret) {
    step('Забираем сессию…', 90);
    return api('/Users/AuthenticateWithQuickConnect', {
      method: 'POST', json: { Secret: secret }
    }).then(function (r) {
      if (!r.ok) throw new Error('Jellyfin не отдал сессию по подтверждённому коду.');
      return r.json();
    });
  }

  tryExisting().then(function (valid) {
    if (valid) { done(); return; }
    step('Готовим вход…', 20);
    return readVersion()
      .then(initiate)
      .then(function (qc) {
        return approve(qc.Code).then(function () { return exchange(qc.Secret); });
      })
      .then(function (result) {
        if (!result || !result.AccessToken) {
          throw new Error('Jellyfin вернул ответ без токена доступа.');
        }
        save(result);
        done();
      });
  }).catch(function (e) {
    fail((e && e.message) || 'Неизвестная ошибка.');
  });
})();
</script>
</body>
</html>
`))
