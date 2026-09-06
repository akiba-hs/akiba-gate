package nextcloud

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/akiba-hs/akiba-gate/internal/auth"
)

// OpenPath — страница-перемычка, с которой начинается переход в Nextcloud.
//
// Зачем она нужна. Сам переход — это выдача одноразового кода, редирект в
// Nextcloud и обмен кода запросом от сервера к серверу. Обмен занимает
// заметное время: Nextcloud идёт к шлюзу и ждёт ответа. Всё это время без
// перемычки человек смотрит на прежнюю страницу и не понимает, нажалась
// ли карточка вообще, — а нажав ещё раз, сжигает выданный код и получает
// «Код входа недействителен».
//
// Страница закрывает ровно этот промежуток: браузер показывает её, пока
// грузится следующий документ, то есть ровно пока идёт обмен.
const OpenPath = "/nextcloud/open"

// OpenHandler показывает перемычку и отправляет браузер за кодом.
type OpenHandler struct {
	// Target — адрес выдачи кода, то есть StartHandler.
	Target string
	Log    *slog.Logger
}

func (h *OpenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Страница персональная и ведёт к выдаче доступа: ни кэшировать её, ни
	// индексировать нельзя.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Referrer-Policy", "no-referrer")
	auth.OwnPageHeaders(w.Header())

	target := h.Target
	if target == "" {
		target = StartPath
	}
	if err := openTemplate.Execute(w, struct{ Target string }{Target: target}); err != nil {
		h.Log.Error("не удалось отрендерить страницу перехода в Nextcloud", "error", err)
	}
}

// openTemplate — та же перемычка, что у Jellyfin: одинаковый переход должен
// выглядеть одинаково, иначе портал кажется собранным из разных программ.
//
// Отличие одно: здесь шлюзу нечего делать в браузере, вся работа идёт на
// сервере. Поэтому шагов два, и второй — уже сам переход.
var openTemplate = template.Must(template.New("nextcloud-open").Parse(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вход в Nextcloud…</title>
<meta name="robots" content="noindex, nofollow">
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; background:#16181d; color:#e8e6e3;
         font:16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
         display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { width:100%; max-width:420px; text-align:center; }
  .ring { width:76px; height:76px; margin:0 auto 26px; position:relative; }
  .ring i { position:absolute; inset:0; border-radius:50%;
            border:3px solid transparent; border-top-color:#0082c9;
            animation:spin 1.1s cubic-bezier(.6,.15,.35,.85) infinite; }
  .ring i:nth-child(2) { inset:11px; border-top-color:#7bc4ea; animation-duration:1.5s;
                         animation-direction:reverse; }
  .ring i:nth-child(3) { inset:22px; border-top-color:#6c7a8f;
                         animation-duration:1.9s; }
  @keyframes spin { to { transform:rotate(360deg); } }
  h1 { font-size:1.15rem; font-weight:600; margin:0 0 8px; }
  .step { color:#9aa0ab; min-height:1.5em; }
  .bar { height:3px; margin:22px auto 0; max-width:260px; background:#262a33;
         border-radius:3px; overflow:hidden; }
  .bar span { display:block; height:100%; width:0; background:#0082c9;
              border-radius:3px; transition:width .45s ease; }
  @media (prefers-reduced-motion: reduce) {
    .ring i { animation:none; border-color:#3a4150; border-top-color:#0082c9; }
    .bar span { transition:none; }
  }
</style>
<noscript>
  <!-- Без JavaScript переход всё равно обязан состояться: вход не должен
       зависеть от того, что у человека отключены скрипты. -->
  <meta http-equiv="refresh" content="0; url={{.Target}}">
</noscript>
</head>
<body>
<main class="card">
  <div class="ring" aria-hidden="true"><i></i><i></i><i></i></div>
  <h1>Открываем Nextcloud</h1>
  <p class="step" id="step">Готовим вход…</p>
  <div class="bar"><span id="fill"></span></div>
</main>

<script>
(function () {
  var target = {{.Target}};
  var stepEl = document.getElementById('step');
  var fillEl = document.getElementById('fill');

  function step(text, percent) {
    stepEl.textContent = text;
    fillEl.style.width = percent + '%';
  }

  step('Готовим вход…', 35);
  // Небольшая пауза — чтобы первый шаг успел отрисоваться, а не мигнул.
  // Дальше браузер продолжает показывать эту же страницу, пока Nextcloud
  // обменивает код у шлюза, так что индикатор виден всё ожидание.
  setTimeout(function () {
    step('Открываем Nextcloud…', 75);
    // replace, а не assign: «назад» не должно возвращать на перемычку —
    // код уже сгорел, и второй заход показал бы ошибку.
    location.replace(target);
  }, 350);
})();
</script>
</body>
</html>
`))
