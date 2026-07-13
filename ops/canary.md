# Обкатка образа на одном сервере (canary) и возврат на stable

Ручной прогон нового образа релея на **одном** сервере через канал `:canary` —
прежде чем катить на весь флот (`:stable`) через workflow «Promote / rollback».

Модель выката (ДПЛ-5/6): сборка → смоук-тест → авто-публикация только в `:canary`;
`:stable` (весь флот) переставляется вручную (Actions → «Promote / rollback» →
`source=canary`, `target=stable`).

Ниже — Docker-деплой: каталог compose `~/relay`, контейнер `relay-relay-1`.

## Выкатить canary на этот сервер (одна строка)

```bash
cd ~/relay && { grep -q '^LICNO_CHANNEL=' .env && sed -i 's/^LICNO_CHANNEL=.*/LICNO_CHANNEL=canary/' .env || echo 'LICNO_CHANNEL=canary' >> .env; } && docker compose pull relay && docker compose up -d
```

Переключает `.env` на канал `canary`, тянет и запускает канареечный образ.

## Вернуть обратно на stable (одна строка)

```bash
cd ~/relay && sed -i '/^LICNO_CHANNEL=/d' .env && docker compose pull relay && docker compose up -d
```

Убирает строку канала (по умолчанию = `stable`), тянет и запускает стабильный образ.

## Проверка

```bash
docker compose logs --tail=15 relay                                # без ошибок; "Лично relay listening on :8787"
docker inspect --format '{{.State.Health.Status}}' relay-relay-1   # healthy
docker exec relay-relay-1 stat -c %u /proc/1                       # 999 = non-root
```
