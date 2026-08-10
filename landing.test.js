'use strict';

/**
 * landing.test.js — страница знакомства (ВЫП-10).
 *
 * КОГО ЭТА СТРАНИЦА ВСТРЕЧАЕТ
 *
 * Того, у кого приложения ещё нет: код знакомства теперь ссылка, и системная
 * камера открывает её в браузере. Ошибка здесь — это тупик ровно в тот момент,
 * когда человек собрался начать пользоваться, поэтому проверяется не «страница
 * отдалась», а что на ней есть работающий следующий шаг для КАЖДОЙ платформы.
 *
 * Запуск: node server/landing.test.js
 */

const assert = require('assert');

const { platformOffer, landingHtml, escapeHtml } = require('./landing');

let passed = 0;
const ok = (name) => {
  console.log('  ✓ ' + name);
  passed += 1;
};

console.log('\nВЫП-10: страница знакомства\n');

const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15';
const ANDROID = 'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36';
const DESKTOP = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

{
  assert.strictEqual(platformOffer(IPHONE), 'ios');
  assert.strictEqual(platformOffer('Mozilla/5.0 (iPad; CPU OS 17_0)'), 'ios');
  assert.strictEqual(platformOffer(ANDROID), 'android');
  assert.strictEqual(platformOffer(DESKTOP), 'other');
  assert.strictEqual(platformOffer(''), 'other');
  assert.strictEqual(platformOffer(null), 'other');
  ok('платформа определяется по User-Agent, а неизвестное не выдаётся за Android');
}

{
  // ГЛАВНОЕ ДЛЯ iPhone: там приложения нет и не будет — магазина у проекта нет,
  // APK не ставится. Предлагать «скачать» первым было бы издевательством.
  const html = landingHtml({ userAgent: IPHONE, downloadUrl: '/update/file?platform=android', webUrl: '/app' });
  const firstButton = html.slice(html.indexOf('class="btn"'), html.indexOf('class="btn"') + 120);
  assert.ok(firstButton.includes('/app'), 'на iPhone первой кнопкой предлагают скачать APK, который туда не ставится');
  // И сказано, как получить уведомления: без «на экран Домой» их на iPhone не будет.
  assert.ok(html.includes('На экран'), 'на iPhone не сказано, как добавить веб-версию на экран «Домой»');
  assert.ok(html.includes('уведомления'), 'не сказано, чем грозит открытие просто во вкладке');
  ok('на iPhone первой идёт веб-версия и объяснено про «На экран «Домой»»');
}

{
  const html = landingHtml({ userAgent: ANDROID, downloadUrl: '/update/file?platform=android', webUrl: '/app' });
  const firstButton = html.slice(html.indexOf('class="btn"'), html.indexOf('class="btn"') + 120);
  assert.ok(firstButton.includes('/update/file'), 'на Android первой кнопкой не предлагают приложение');
  ok('на Android первой идёт установка приложения');
}

{
  // Второй путь виден ВСЕГДА: определение по User-Agent не бывает точным, и
  // тупика быть не должно ни при какой ошибке распознавания.
  for (const [name, ua] of [['iPhone', IPHONE], ['Android', ANDROID], ['десктоп', DESKTOP], ['пусто', '']]) {
    const html = landingHtml({ userAgent: ua, downloadUrl: '/update/file?platform=android', webUrl: '/app' });
    assert.ok(html.includes('/app'), `${name}: нет пути к веб-версии`);
    assert.ok(html.includes('/update/file'), `${name}: нет пути к приложению`);
  }
  ok('оба пути видны на любой платформе — ошибка распознавания не создаёт тупик');
}

{
  // Ни одного внешнего ресурса: страницу открывают там, где приложения нет, — в
  // том числе там, где всё лишнее заблокировано. И никаких счётчиков: узлу
  // незачем знать, кто с кем знакомится.
  const html = landingHtml({ userAgent: ANDROID, downloadUrl: '/update/file', webUrl: '/app' });
  assert.strictEqual(/src\s*=\s*"https?:/i.test(html), false, 'на странице внешний ресурс');
  assert.strictEqual(/href\s*=\s*"https?:/i.test(html), false, 'на странице внешняя ссылка');
  assert.strictEqual(/<script/i.test(html), false, 'на странице скрипт — она обязана работать без него');
  ok('ни внешних ресурсов, ни скриптов, ни счётчиков');
}

{
  // Разметка не собирается из непроверенного: адреса приходят параметрами, и
  // кавычка в них разорвала бы атрибут.
  const html = landingHtml({
    userAgent: ANDROID,
    downloadUrl: '"><script>alert(1)</script>',
    webUrl: '/app',
  });
  assert.strictEqual(/<script>alert/i.test(html), false, 'адрес попал в разметку неэкранированным');
  assert.strictEqual(escapeHtml('<a href="x">&'), '&lt;a href=&quot;x&quot;&gt;&amp;');
  ok('адреса экранируются перед подстановкой в разметку');
}

{
  // Данных знакомства на странице нет и быть не может: они во фрагменте ссылки,
  // а он на сервер не отправляется. Проверяем, что мы их и не пытаемся показать.
  const html = landingHtml({ userAgent: ANDROID, downloadUrl: '/update/file', webUrl: '/app' });
  assert.ok(html.includes('на сервер он не уходит'), 'человеку не сказано, что его код остался в браузере');
  assert.ok(html.includes('отсканируйте код ещё раз'), 'человеку не сказано, что делать после установки');
  assert.ok(html.includes('несколько секунд'), 'не объяснено, почему код перестал действовать');
  ok('сказано, что код на сервер не уходит и что делать после установки');
}

console.log(`\nВЫП-10 (страница): ${passed} проверок пройдено`);
