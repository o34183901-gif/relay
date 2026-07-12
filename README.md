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

Нужен сервер (Ubuntu подойдёт) с открытыми портами **80** и **443**.
Caddy сам получит TLS-сертификат, так что приложение сразу видит рабочий `wss://`.

```bash
# 1) Docker (если ещё не установлен)
curl -fsSL https://get.docker.com | sh

# 2) Релей
git clone https://github.com/o34183901-gif/relay.git
cd relay
cp .env.example .env
nano .env            # RELAY_HOST, RELAY_SELF_URL, RELAY_PEERS, TURN_HOST, TURN_SECRET
docker compose up -d
```

### Что писать в .env

| Переменная | Что это |
|------------|---------|
| `RELAY_HOST` | Публичный хост для TLS. Без домена — `<IP-с-точками>.sslip.io` (напр. `203.0.113.7.sslip.io`) |
| `RELAY_SELF_URL` | Как релей анонсирует себя: обычно `wss://<RELAY_HOST>` |
| `RELAY_PEERS` | **Сосед(и)** — уже работающий релей, чтобы влиться в сеть. Первый релей в сети — оставить пустым |
| `TURN_HOST` | Публичный **IP** сервера (без `.sslip.io`) — для звонков |
| `TURN_SECRET` | Случайная строка для TURN. Сгенерировать: `openssl rand -hex 32` |

**Первый релей в сети** (ему не к кому подключаться):
```ini
RELAY_HOST=203.0.113.7.sslip.io
RELAY_SELF_URL=wss://203.0.113.7.sslip.io
RELAY_PEERS=
TURN_HOST=203.0.113.7
TURN_SECRET=<openssl rand -hex 32>
```

**Каждый следующий релей** (вливается через любой живой узел):
```ini
RELAY_HOST=198.51.100.9.sslip.io
RELAY_SELF_URL=wss://198.51.100.9.sslip.io
RELAY_PEERS=wss://203.0.113.7.sslip.io
TURN_HOST=198.51.100.9
TURN_SECRET=<openssl rand -hex 32>
```

### Порты firewall

Звонки включены по умолчанию (coturn), поэтому откройте:

| Порт | Назначение |
|------|-----------|
| `80/tcp`, `443/tcp` | TLS + WebSocket (Caddy) |
| `3478/tcp`, `3478/udp` | TURN (звонки) |
| `49160-49200/udp` | медиа-диапазон TURN |

```bash
sudo ufw allow 80,443,3478/tcp && sudo ufw allow 3478/udp && sudo ufw allow 49160:49200/udp
```

### Автозапуск после перезагрузки

Ничего дополнительно делать не нужно: у всех сервисов `restart: unless-stopped`, а
демон Docker включён в автозапуск systemd. После ребута сервера релей, Caddy и
coturn поднимутся сами. Проверить, что Docker стартует на загрузке:
`sudo systemctl is-enabled docker` → `enabled` (иначе `sudo systemctl enable docker`).

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

## Удаление старой установки (bare-metal через install.sh)

Если раньше релей ставился скриптом (systemd-сервис `licno-relay` + Caddy +
coturn), его нужно удалить — **обязательно** перед запуском Docker на том же
сервере, иначе порты 80/443/3478 заняты и контейнеры не стартуют.

```bash
# 1) остановить и удалить сам релей
sudo systemctl stop licno-relay
sudo systemctl disable licno-relay
sudo rm -f /etc/systemd/system/licno-relay.service
sudo systemctl daemon-reload
sudo rm -rf /opt/licno-relay        # код + очередь/каталог/токены

# 2) освободить порты 80/443 и 3478 — остановить bare-metal Caddy и coturn
sudo systemctl stop caddy coturn
sudo systemctl disable caddy coturn

# (по желанию — полностью удалить пакеты)
sudo apt-get remove --purge -y caddy coturn
```

Проверка, что порты свободны: `sudo ss -tulpn | grep -E ':(80|443|3478)\b'`
должно ничего не вернуть. После этого — `docker compose up -d`.

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
