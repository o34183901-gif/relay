# Релей «Лично»

Store-and-forward ретранслятор для мессенджера «Лично». Доставляет **зашифрованные**
сообщения между телефонами по WebSocket и держит реплицированный каталог релеев
(gossip), чтобы сеть росла без единой точки отказа.

> Релей видит только шифртекст и публичный ключ получателя — **ни текста, ни
> вложений, ни имён прочитать не может**. Содержимое E2E-зашифровано на устройствах.

Код сервера синхронизируется из основного репозитория приложения; здесь — всё
необходимое, чтобы поднять свой релей. Клиентских исходников тут нет.

---

## Запуск: Docker Compose (рекомендуется)

Нужен сервер с Docker (Ubuntu подойдёт) и открытыми портами **80** и **443**.
Caddy сам получит TLS-сертификат, так что приложение сразу видит рабочий `wss://`.

```bash
git clone https://github.com/o34183901-gif/relay.git
cd relay
cp .env.example .env
nano .env            # заполнить RELAY_HOST, RELAY_SELF_URL, RELAY_PEERS
docker compose up -d
```

### Что писать в .env

| Переменная | Что это |
|------------|---------|
| `RELAY_HOST` | Публичный хост для TLS. Без домена — `<IP-с-точками>.sslip.io` (напр. `203.0.113.7.sslip.io`) |
| `RELAY_SELF_URL` | Как релей анонсирует себя: обычно `wss://<RELAY_HOST>` |
| `RELAY_PEERS` | **Сосед(и)** — уже работающий релей, чтобы влиться в сеть. Здесь указываете пир. Первый релей в сети — оставить пустым |

**Первый релей в сети** (ему не к кому подключаться):
```ini
RELAY_HOST=203.0.113.7.sslip.io
RELAY_SELF_URL=wss://203.0.113.7.sslip.io
RELAY_PEERS=
```

**Каждый следующий релей** (вливается через любой живой узел):
```ini
RELAY_HOST=198.51.100.9.sslip.io
RELAY_SELF_URL=wss://198.51.100.9.sslip.io
RELAY_PEERS=wss://203.0.113.7.sslip.io
```

### Звонки (по желанию)

```bash
# заполнить TURN_SECRET (случайная строка) и TURN_HOST (публичный IP) в .env
docker compose --profile calls up -d
```

---

## Проверка

```bash
curl https://<RELAY_HOST>/health     # {"ok":true,"relays":N,...}
curl https://<RELAY_HOST>/relays     # список известных релеев (растёт через gossip)
docker compose logs -f relay         # логи релея
```

## Обновление

```bash
cd relay && git pull
docker compose up -d --build          # пересобрать и перезапустить
```

## Как это масштабируется

Каждый релей хранит список известных релеев и синхронизирует его с соседями
(`GET /relays`, gossip). Новый узел, указавший в `RELAY_PEERS` любой живой релей,
за пару минут становится известен всей сети — **без обновления приложения**. В
приложении на экране контактов растёт счётчик «Серверов в сети».

---

## Альтернатива без Docker (bare-metal)

Скрипт ставит Node.js, systemd-сервис, firewall, Caddy (авто-TLS) и coturn:

```bash
git clone https://github.com/o34183901-gif/relay.git && cd relay
sudo RELAY_PEERS="wss://<живой-релей>" bash install.sh <RELAY_HOST>
# первый релей: без RELAY_PEERS ->  sudo bash install.sh <RELAY_HOST>
```

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|------------|--------------|-----------|
| `RELAY_SELF_URL` | — | Публичный `wss://`-адрес релея (в каталог) |
| `RELAY_PEERS` | — | Стартовые соседи через запятую |
| `RELAY_GOSSIP_MS` | `60000` | Период синхронизации каталога |
| `PORT` | `8787` | Порт релея |
| `RELAY_DATA`/`RELAY_DIR`/`RELAY_PUSH`/`RELAY_IDENT` | `/data/*` | Файлы рантайма |
| `TURN_SECRET`/`TURN_HOST` | — | Ephemeral TURN-креды для звонков |
| `FCM_PROJECT_ID` + `GOOGLE_APPLICATION_CREDENTIALS` | — | Пуши при закрытом приложении (FCM) |
