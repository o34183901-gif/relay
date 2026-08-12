const BUILD_ID = '20260812072012-d1ea463d';
const CACHE_NAME = `licno-pwa-${BUILD_ID}`;
const APP_ROOT = '/app/';
const SHELL = [
  APP_ROOT,
  `${APP_ROOT}manifest.webmanifest`,
  `${APP_ROOT}icons/icon-1024.png`,
  `${APP_ROOT}icons/icon-maskable-1024.png`,
  // UI-5: воркер расшифровки вложений и его копия nacl. Кладём в оболочку, чтобы
  // после установки они были на месте сразу и офлайн: без воркера расшифровка
  // уедет в главный поток, и чат снова начнёт подвисать при открытии.
  `${APP_ROOT}attachment-decrypt-worker.js`,
  `${APP_ROOT}nacl-fast.min.js`,
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(
          names
            .filter((name) => name.startsWith('licno-pwa-') && name !== CACHE_NAME)
            .map((name) => caches.delete(name))
        )
      )
      .then(() => self.clients.claim())
  );
});

async function networkFirst(request) {
  const cache = await caches.open(CACHE_NAME);
  try {
    const fresh = await fetch(request, { cache: 'no-store' });
    if (fresh && fresh.ok) await cache.put(request, fresh.clone());
    return fresh;
  } catch (error) {
    return (await cache.match(request)) || (await cache.match(APP_ROOT));
  }
}

async function cacheFirst(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  if (cached) return cached;
  const fresh = await fetch(request);
  if (fresh && fresh.ok) await cache.put(request, fresh.clone());
  return fresh;
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(APP_ROOT)) return;
  if (url.pathname === `${APP_ROOT}sw.js` || url.pathname === `${APP_ROOT}version.json`) return;
  if (request.mode === 'navigate') {
    event.respondWith(networkFirst(request));
    return;
  }
  event.respondWith(cacheFirst(request));
});

// ПРФ-4: уведомления разных чатов больше не затирают друг друга.
//
// Раньше все сообщения показывались под ОДНИМ тегом licno-new-message и без
// renotify: каждое следующее беззвучно заменяло предыдущее. Пять сообщений из
// трёх чатов давали одно безымянное уведомление — пользователь заключал, что
// часть сообщений потерялась.
//
// Теперь релей кладёт в тело пуша непрозрачный признак чата (chatTag — хэш
// адреса отправителя). Тело web-push зашифровано ключами подписки, поэтому
// провайдер пуша его не видит; для нас же этого достаточно, чтобы дать каждому
// чату свою ветку уведомлений. Имени отправителя здесь по-прежнему нет: service
// worker не имеет доступа к расшифрованной адресной книге, а возить имя через
// сервер значило бы раскрыть ему социальный граф.
function notificationTagFor(data) {
  if (data && data.title === 'Входящий звонок') return 'licno-call';
  const chatTag = data && typeof data.chatTag === 'string' ? data.chatTag : '';
  // Признак недоверенный — пропускаем только безопасный алфавит.
  if (/^[A-Za-z0-9_-]{1,64}$/.test(chatTag)) return 'licno-chat-' + chatTag;
  return 'licno-new-message'; // старый релей без chatTag — прежнее поведение
}

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (error) {}
  event.waitUntil(
    self.registration.showNotification(data.title || 'Лично', {
      body: data.body || 'Новое зашифрованное сообщение',
      tag: notificationTagFor(data),
      // Замена уведомления в пределах ОДНОГО чата должна быть заметной: иначе
      // новое сообщение подменяет старое совершенно беззвучно.
      renotify: true,
      icon: `${APP_ROOT}icons/icon-1024.png`,
      badge: `${APP_ROOT}icons/icon-1024.png`,
      data: { url: APP_ROOT },
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      const existing = clients.find((client) => new URL(client.url).pathname.startsWith(APP_ROOT));
      if (existing) {
        existing.navigate(APP_ROOT);
        return existing.focus();
      }
      return self.clients.openWindow(APP_ROOT);
    })
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});
