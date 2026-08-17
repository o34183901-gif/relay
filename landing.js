'use strict';

function platformOffer(userAgent) {
  const ua = String(userAgent || '');
  if (/iPhone|iPad|iPod/i.test(ua)) return 'ios';
  if (/Android/i.test(ua)) return 'android';
  return 'other';
}

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function landingHtml({ userAgent, downloadUrl, webUrl }) {
  const offer = platformOffer(userAgent);
  const download = escapeHtml(downloadUrl || '');
  const web = escapeHtml(webUrl || '/app');
  const primary =
    offer === 'ios'
      ? `<a class="btn" href="${web}">Открыть «Лично» в браузере</a>`
      : `<a class="btn" href="${download}">Скачать приложение</a>`;
  const secondary =
    offer === 'ios'
      ? `<a class="alt" href="${download}">Скачать приложение (Android)</a>`
      : `<a class="alt" href="${web}">Открыть в браузере</a>`;
  const iosHint =
    offer === 'ios'
      ? `<p class="hint"><b>Чтобы «Лично» открывалось как приложение:</b> нажмите
         «Поделиться» внизу браузера и выберите «На экран «Домой»». Иначе уведомления
         о сообщениях приходить не будут — так устроен iPhone, а не наш выбор.</p>`
      : '';
  const nextStep = `<p class="hint"><b>Что дальше:</b> откройте «Лично» и
     отсканируйте код ещё раз — попросите показать его снова. Код действует
     несколько секунд, поэтому знакомство всегда завершается очно: именно это и
     защищает от подмены собеседника.</p>`;
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Лично — знакомство по коду</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:#07101A; color:#E8EEF6; font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  main { max-width:26rem; padding:2rem 1.25rem; }
  h1 { font-size:1.5rem; margin:0 0 .5rem; }
  p { margin:0 0 1rem; color:#A9BACD; }
  .btn { display:block; padding:.9rem 1rem; margin:1.25rem 0 .75rem; border-radius:.75rem;
         background:#2E7DF7; color:#fff; text-align:center; text-decoration:none; font-weight:600; }
  .alt { display:block; text-align:center; color:#8FB4EA; text-decoration:none; padding:.5rem; }
  .hint { font-size:.9rem; background:#0E1B2A; border-radius:.75rem; padding:.9rem 1rem; }
  .quiet { font-size:.85rem; color:#6F8296; margin-top:1.5rem; }
</style>
</head>
<body>
<main>
  <h1>Вас пригласили в «Лично»</h1>
  <p>Мессенджер со сквозным шифрованием: без номера телефона, без регистрации,
     без слежки. Переписку не может прочитать никто, включая серверы, через
     которые она идёт.</p>
  ${primary}
  ${secondary}
  ${iosHint}
  ${nextStep}
  <p class="quiet">Код знакомства живёт несколько секунд и остаётся в адресной
     строке вашего браузера — на сервер он не уходит. После установки попросите
     показать код ещё раз: знакомство очное, и это не формальность, а
     единственное, что защищает от подмены собеседника.</p>
</main>
</body>
</html>
`;
}
module.exports = { platformOffer, landingHtml, escapeHtml };