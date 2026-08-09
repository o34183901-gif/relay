/* ЭТОТ ФАЙЛ СГЕНЕРИРОВАН — НЕ РЕДАКТИРУЙТЕ ЕГО.
 * Источник: src/nativeEd25519.js
 * Перегенерировать: node scripts/sync-core.js
 *
 * Правки вносятся ТОЛЬКО в источник. Ручная правка этой копии будет затёрта,
 * а CI (`node scripts/sync-core.js --check`) не пропустит расхождение: именно
 * оно однажды стоило потерянных сообщений на компьютере (НАД-1).
 */
/**
 * nativeEd25519.js — подпись через OpenSSL там, где до него можно дотянуться (НАТ-1).
 *
 * ЗАЧЕМ
 *
 * Ed25519 — самая дорогая операция во всём проекте, и она не редкая: релей
 * проверяет подпись на каждое подключение (challenge), на подписанный список
 * устройств в каждом конверте, на каждую записку флота. ВЫС-10 уже перевёл эти
 * пути с tweetnacl на @noble/curves и выиграл порядок. Дальше упирается в то,
 * что @noble — это JavaScript и BigInt.
 *
 * Замер на этой машине, проверка подписи с честным разбором ключа на каждый
 * вызов (ключ приезжает из сети, держать его негде):
 *
 *   tweetnacl      12,25 мс
 *   @noble/curves   1,61 мс
 *   OpenSSL         0,12 мс     ← ×13 к noble, ×100 к tweetnacl
 *
 * Создание подписи: noble 0,40 мс, OpenSSL 0,081 мс — ×5.
 *
 * ЧТО ЗДЕСЬ
 *
 * Превращение Node-подобного `crypto` в ту же пару `{ sign, verify }`, которую
 * ждёт src/ed25519.js. Node-подобный — значит `createPrivateKey`,
 * `createPublicKey`, `sign`, `verify`: ровно то, что даёт `node:crypto` на
 * релее и на настольном клиенте.
 *
 * ПОЧЕМУ ЧЕРЕЗ DER, А НЕ ЧЕРЕЗ СЫРЫЕ БАЙТЫ
 *
 * OpenSSL не принимает 32 байта ключа как есть — ему нужен ключ в оболочке
 * (PKCS#8 для секретного, SPKI для открытого). Оболочка для Ed25519
 * фиксированной длины и целиком состоит из идентификатора кривой, поэтому
 * «преобразование» здесь — это приписать спереди известные 12 или 16 байт.
 * Никакого разбора ASN.1 писать не нужно, и именно поэтому это делается тут, а
 * не тянется зависимостью.
 *
 * ПОЧЕМУ КЭША КЛЮЧЕЙ НЕТ
 *
 * Напрашивается запоминать разобранные ключи: собеседник шлёт много конвертов
 * подряд. Замер говорит, что не стоит — разбор открытого ключа стоит 0,011 мс,
 * то есть девять процентов проверки, и кэш даёт 13,2 против 14,4 крат. За эти
 * проценты пришлось бы платить картой, которая растёт от ключей ИЗ СЕТИ, то
 * есть от того, что выбирает не наша сторона. Плохой размен.
 *
 * ПОЧЕМУ ЗДЕСЬ ЕСТЬ САМОПРОВЕРКА
 *
 * Это подпись, и на ней держится вопрос «кто это написал». Реализация приезжает
 * из окружения: сборка OpenSSL может оказаться без Ed25519, версия — сменить
 * форму аргументов, платформа — вернуть подпись в другом порядке байтов. Ошибка
 * при этом не выглядит ошибкой. Хуже того, самая опасная поломка — не «ничего не
 * работает», а «проверка возвращает true всегда»: тогда чужой конверт проходит
 * как свой, и заметить это некому.
 *
 * Поэтому перед включением реализация обязана предъявить известный ответ на
 * вектор из RFC 8032 (§7.1, TEST 2) — тот же байт в байт, что дают tweetnacl и
 * @noble/curves (сверено, см. test/nativeEd25519.test.js), — и обязана ОТКАЗАТЬ
 * на подделанной подписи, на подменённом сообщении и на чужом ключе. Не сошлось
 * хоть что-то — реализация не включается вовсе, и подпись идёт прежним путём.
 *
 * Модуль чистый: ни React, ни платформенных зависимостей, `crypto` приходит
 * снаружи. Тест — test/nativeEd25519.test.js.
 */
'use strict';

/**
 * Оболочка PKCS#8 для секретного ключа Ed25519: версия, идентификатор кривой
 * (1.3.101.112) и заголовок строки из 32 байт. Дальше идёт seed.
 */
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** Оболочка SPKI для открытого ключа Ed25519. Дальше идут 32 байта ключа. */
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** Длина ключа Ed25519 — и открытого, и семени секретного. */
const KEY_LENGTH = 32;

/** Длина подписи Ed25519. */
const SIGNATURE_LENGTH = 64;

/**
 * Известный ответ: RFC 8032, §7.1, TEST 2.
 *
 * Взят из стандарта, а не посчитан нашим же кодом, — иначе самопроверка
 * проверяла бы реализацию ею самой. То, что тот же ответ дают tweetnacl и
 * @noble/curves, закреплено отдельной проверкой в тесте.
 */
const VECTOR = {
  seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
  publicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  message: '72',
  signature:
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' +
    '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
};

function fromHex(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.substr(i * 2, 2), 16);
  return out;
}

function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/**
 * Склеить оболочку и ключ.
 *
 * Копия, а не срез поверх чужой памяти: ключ может приехать видом на больший
 * буфер (`subarray` от 64-байтной секретки — обычное дело), и передавать такой
 * вид дальше означало бы зависеть от того, как принимающая сторона читает
 * byteOffset.
 */
function wrap(prefix, key) {
  const out = new Uint8Array(prefix.length + KEY_LENGTH);
  out.set(prefix, 0);
  out.set(key.subarray(0, KEY_LENGTH), prefix.length);
  return out;
}

function copy(value) {
  const out = new Uint8Array(value.length);
  out.set(value, 0);
  return out;
}

/**
 * Построить реализацию подписи поверх Node-подобного `crypto`.
 *
 * Возвращает `{ sign, verify }` либо null, если у объекта нет нужных методов.
 * Ничего не проверяет по существу — это делает `selfTest`.
 */
function createNativeEd25519(nodeCrypto) {
  if (
    !nodeCrypto ||
    typeof nodeCrypto.createPrivateKey !== 'function' ||
    typeof nodeCrypto.createPublicKey !== 'function' ||
    typeof nodeCrypto.sign !== 'function' ||
    typeof nodeCrypto.verify !== 'function'
  ) {
    return null;
  }

  return {
    /**
     * Подписать. `secretKey` — 64 байта в формате tweetnacl (seed + открытый
     * ключ); OpenSSL нужен только seed, открытую часть он выводит сам.
     */
    sign(message, secretKey) {
      const key = nodeCrypto.createPrivateKey({
        key: wrap(PKCS8_PREFIX, secretKey),
        format: 'der',
        type: 'pkcs8',
      });
      // Первым аргументом null — это и означает Ed25519: подпись берётся от
      // самого сообщения, а не от его хеша. Передать сюда имя хеша нельзя,
      // OpenSSL на этом откажет.
      return copy(nodeCrypto.sign(null, message, key));
    },

    /**
     * Проверить.
     *
     * Любая ошибка — это «подпись не сошлась», а не исключение: и сообщение, и
     * подпись, и ключ приезжают из сети, и бросать здесь означало бы отдать
     * отправителю управление потоком выполнения. Ловить есть что: на `null`
     * вместо подписи OpenSSL бросает TypeError (проверено).
     *
     * ДЛИНУ КЛЮЧА проверяем сами, и это не перестраховка. Склейка дополняет
     * короткий ключ нулями до тридцати двух байт, а OpenSSL разбирает
     * получившееся как совершенно законный — просто ДРУГОЙ — ключ. Замерено: у
     * ключа, кончающегося нулевым байтом, тридцать один байт хватает, чтобы
     * подпись сошлась. То есть один ключ получает несколько представлений, и
     * слой выше — который сверяет присланный ключ с ключом контакта строкой —
     * их не сопоставит. Длина обязана быть ровно тридцать два.
     *
     * Длину ПОДПИСИ не проверяем: OpenSSL отвергает чужую сам, возвращая false,
     * а не бросая (тоже проверено). Лишнее условие здесь только создавало бы
     * вид защиты там, где её обеспечивает нижний слой.
     */
    verify(message, signature, publicKey) {
      try {
        if (!publicKey || publicKey.length !== KEY_LENGTH) return false;
        const key = nodeCrypto.createPublicKey({
          key: wrap(SPKI_PREFIX, publicKey),
          format: 'der',
          type: 'spki',
        });
        return nodeCrypto.verify(null, message, key, signature) === true;
      } catch (error) {
        return false;
      }
    },
  };
}

/**
 * Проверить, что реализация делает ИМЕННО Ed25519, а не что-то похожее.
 *
 * Пять проверок, и каждая закрывает свой способ ошибиться:
 *
 *   1. подпись совпала с вектором из стандарта — алгоритм и порядок байтов те;
 *   2. своя подпись проверяется — sign и verify говорят на одном языке;
 *   3. подделанная подпись отвергнута;
 *   4. подменённое сообщение отвергнуто;
 *   5. чужой ключ отвергнут.
 *
 * Три последние важнее первых двух. Реализация, которая всегда возвращает true,
 * проходит проверку «своя подпись сходится» и выглядит рабочей ровно до дня,
 * когда кто-то подпишет чужим ключом.
 *
 * Возвращает причину отказа строкой либо null, если всё сошлось.
 */
function selfTest(implementation) {
  if (!implementation) return 'нет реализации';
  const seed = fromHex(VECTOR.seed);
  const publicKey = fromHex(VECTOR.publicKey);
  const message = fromHex(VECTOR.message);
  const expected = VECTOR.signature;

  // Секретка в формате tweetnacl — seed и следом открытый ключ.
  const secretKey = new Uint8Array(64);
  secretKey.set(seed, 0);
  secretKey.set(publicKey, KEY_LENGTH);

  const signature = implementation.sign(message, secretKey);
  if (!signature || signature.length !== SIGNATURE_LENGTH) return 'подпись не той длины';
  if (toHex(signature) !== expected) return 'подпись не совпала с вектором RFC 8032';

  if (implementation.verify(message, signature, publicKey) !== true) {
    return 'собственная подпись не проверяется';
  }

  const damaged = copy(signature);
  damaged[damaged.length - 1] ^= 0xff;
  if (implementation.verify(message, damaged, publicKey) !== false) {
    return 'подделанная подпись принята';
  }

  const otherMessage = Uint8Array.from([...message, 0x00]);
  if (implementation.verify(otherMessage, signature, publicKey) !== false) {
    return 'подпись принята под другим сообщением';
  }

  const otherKey = copy(publicKey);
  otherKey[0] ^= 0xff;
  if (implementation.verify(message, signature, otherKey) !== false) {
    return 'подпись принята под чужим ключом';
  }

  return null;
}

/**
 * Найти реализацию и вернуть её, если она прошла самопроверку.
 *
 * Возвращает `{ implementation, reason }`: реализация либо null, и причина, по
 * которой не включили. Причину возвращаем, а не глотаем: «почему-то медленно»
 * без объяснения разбирать нечем.
 */
function resolveNativeEd25519(load) {
  let nodeCrypto = null;
  try {
    nodeCrypto = typeof load === 'function' ? load() : null;
  } catch (error) {
    return { implementation: null, reason: `модуль не загрузился: ${(error && error.message) || error}` };
  }
  const implementation = createNativeEd25519(nodeCrypto);
  if (!implementation) return { implementation: null, reason: 'модуль без нужных методов' };

  let failure;
  try {
    failure = selfTest(implementation);
  } catch (error) {
    failure = `самопроверка бросила ошибку: ${(error && error.message) || error}`;
  }
  return failure ? { implementation: null, reason: failure } : { implementation, reason: null };
}

module.exports = {
  PKCS8_PREFIX,
  SPKI_PREFIX,
  KEY_LENGTH,
  SIGNATURE_LENGTH,
  VECTOR,
  createNativeEd25519,
  selfTest,
  resolveNativeEd25519,
};
