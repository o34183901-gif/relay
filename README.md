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
nano .env            # RELAY_HOST, RELAY_SELF_URL, RELAY_PEERS, TURN_HOST
docker compose up -d
```

### Что писать в .env

| Переменная | Что это |
|------------|---------|
| `RELAY_HOST` | Публичный хост для TLS. Без домена — `<IP-с-точками>.sslip.io` (напр. `203.0.113.7.sslip.io`) |
| `RELAY_SELF_URL` | Как релей анонсирует себя: обычно `wss://<RELAY_HOST>` |
| `RELAY_PEERS` | **Сосед(и)** — уже работающий релей, чтобы влиться в сеть. Первый релей в сети — оставить пустым |
| `TURN_HOST` | Публичный **IP** сервера (без `.sslip.io`) — для звонков |

> `TURN_SECRET` больше не нужен: релей сам генерирует его в томе `/data` (0600) и
> пишет конфиг встроенного coturn — секрета нет в env, аргументах и логах (H-2).

**Первый релей в сети** (ему не к кому подключаться):
```ini
RELAY_HOST=203.0.113.7.sslip.io
RELAY_SELF_URL=wss://203.0.113.7.sslip.io
RELAY_PEERS=
TURN_HOST=203.0.113.7
```

**Каждый следующий релей** (вливается через любой живой узел):
```ini
RELAY_HOST=198.51.100.9.sslip.io
RELAY_SELF_URL=wss://198.51.100.9.sslip.io
RELAY_PEERS=wss://203.0.113.7.sslip.io
TURN_HOST=198.51.100.9
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

## Мониторинг: /metrics (Prometheus)

Полная приборная панель узла — соединения, глубина/вес очереди (включая
вложения на диске), сообщений принято/доставлено/подтверждено, пуши, память:

```bash
curl https://<RELAY_HOST>/metrics
```

Формат стандартный (Prometheus text), подключается к Prometheus/Grafana как
обычный scrape-target. **По умолчанию `/metrics` доступен ТОЛЬКО из приватной
сети/localhost** (M-1): внешний scrape через Caddy отклоняется (403) — команда
`curl https://<RELAY_HOST>/metrics` снаружи вернёт `forbidden`. Скрейпить можно с
самого хоста/из внутренней сети, либо задать `RELAY_METRICS_TOKEN` в `.env` —
тогда endpoint доступен извне по `?token=...` или заголовку
`Authorization: Bearer ...`.

## Пуши при закрытом приложении (FCM)

Чтобы релей мог «будить» телефоны уведомлениями, ему нужен ключ сервисного
аккаунта Firebase **того же проекта, что вшит в приложение**. Файл выдаёт
владелец приложения — релеям со случайными ключами пуши работать не будут.

Как включить (Docker):

```bash
# файл service-account.json лежит рядом, контейнер запущен
docker compose cp ./service-account.json relay:/data/service-account.json
docker compose restart relay
docker compose logs relay | grep push
#   → "[push] FCM configured — wake-up pushes enabled"
```

Файл лежит в томе `/data`, поэтому переживает и рестарты, и авто-обновления.
Ничего в `.env` прописывать не нужно: релей сам находит
`/data/service-account.json` и берёт `project_id` из него (env-переменные
`FCM_PROJECT_ID`/`GOOGLE_APPLICATION_CREDENTIALS` по-прежнему работают и имеют
приоритет). Bare-metal: положите файл рядом с `install.sh` до установки — он
подхватится автоматически, или рядом с `relay.js` у работающего сервера.

Приватность: пуш не содержит ни текста, ни имени отправителя — только сигнал
«есть новое сообщение».

## Авто-обновление (без ручного захода на каждый сервер)

Релей следит за каналом `ghcr.io/o34183901-gif/relay:stable`. Обновление
применяет **верифицированный апдейтер на хосте** (systemd-таймер, раз в 5 минут):
он **проверяет cosign-подпись** образа (provenance: собран нашим CI на `main`) и
только при валидной подписи поднимает новый образ. Значит **обновить тысячи
релеев = один push** (push в этот репозиторий → CI собирает, подписывает и пушит
образ → релеи проверяют подпись и подтягивают его сами). Контейнера с доступом к
`docker.sock` больше нет — это устраняет supply-chain-риск watchtower (H-1).

**Разовая настройка** (образ должен тянуться без логина + поставить апдейтер):
1. Сделайте пакет образа публичным: GitHub → **Packages** → `relay` →
   **Package settings** → **Change visibility** → **Public**.
2. На сервере из каталога репозитория:
   ```bash
   cd relay && git pull
   docker compose pull && docker compose up -d --remove-orphans   # уйти на :stable, убрать старый watchtower
   sudo bash deploy/install-updater.sh                            # cosign + systemd-таймер проверки подписи
   ```

Проверка: `systemctl list-timers licno-update.timer` и
`journalctl -u licno-update.service -n 50 --no-pager` (должно быть «подпись OK»).

**Каналы и откат** (E/D):
- `:stable` — за ним следит весь флот; `:canary` — для обкатки (на канареечном
  сервере добавьте строку `LICNO_CHANNEL=canary` в `.env` — и compose, и апдейтер
  подхватят канал); `:sha-<commit>` — иммутабельные теги для форензики/отката.
- Промоушен/откат — workflow **Promote / rollback** (Actions → Run workflow):
  перевести `:stable` на `:canary` или на конкретный `:sha-…` (ретег по digest —
  cosign-подпись сохраняется).

> Хотите собирать локально вместо готового образа — раскомментируйте `build: .`
> в `docker-compose.yml` (тогда авто-обновления нет, обновляйте
> `git pull && docker compose up -d --build`).

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
| `RELAY_BLOB_THRESHOLD` | `65536` | Конверт крупнее (байт) хранится файлом, не в БД |
| `RELAY_BLOB_DIR` | `/data/blobs` | Каталог blob-вложений (в том же volume) |
| `RELAY_METRICS_TOKEN` | — | Если задан, `/metrics` требует токен |
| `TURN_SECRET`/`TURN_HOST` | — | Ephemeral TURN-креды для звонков |
| `FCM_PROJECT_ID` + `GOOGLE_APPLICATION_CREDENTIALS` | — | Пуши при закрытом приложении (FCM) |
