/* ЭТОТ ФАЙЛ СГЕНЕРИРОВАН — НЕ РЕДАКТИРУЙТЕ ЕГО.
 * Источник: src/nativeX25519.js
 * Перегенерировать: node scripts/sync-core.js
 *
 * Правки вносятся ТОЛЬКО в источник. Ручная правка этой копии будет затёрта,
 * а CI (`node scripts/sync-core.js --check`) не пропустит расхождение: именно
 * оно однажды стоило потерянных сообщений на компьютере (НАД-1).
 */
/**
 * nativeX25519.js — общий секрет через OpenSSL (НАТ-2).
 *
 * ЗАЧЕМ
 *
 * Замер одного общего секрета: tweetnacl 0,646 мс, OpenSSL 0,035 мс — ×18. На
 * релее это путь доказательства владения адресом: общий секрет считается на
 * КАЖДОЕ подключение, а узел однопоточный. У клиента этим же считается каждый
 * шаг храповика с новым ключом и каждое установление сессии.
 *
 * ЧТО ЗДЕСЬ
 *
 * То же, что в nativeEd25519.js, и по тем же причинам: Node-подобный `crypto`
 * приходит снаружи, ключи заворачиваются в PKCS#8 и SPKI приписыванием
 * известных байтов, а перед включением реализация обязана предъявить известный
 * ответ.
 *
 * ЧЕМ ЭТА САМОПРОВЕРКА ОТЛИЧАЕТСЯ ОТ ПОДПИСНОЙ
 *
 * У подписи главный вопрос — «не принимает ли она подделку». Здесь главный
 * вопрос другой: **отвергает ли она точку малого порядка**. Такая точка даёт
 * общий секрет, не зависящий от секретки, и это готовый способ подсунуть
 * сообщение от поддельного ключа (КЛТ-4). Поэтому в самопроверке два теста на
 * согласие (вектор из RFC 7748 и симметрия) и один — на отказ, и последний
 * важнее.
 *
 * Отказ засчитывается в любом виде: реализация может бросить (так делает
 * OpenSSL) или вернуть нули (так делает tweetnacl). Оба ответа означают «эта
 * точка не годится» — а привести их к одному виду обязан слой выше,
 * src/x25519.js. Здесь проверяется только то, что реализация не выдала на
 * вырожденной точке РАБОЧИЙ секрет.
 *
 * Модуль чистый: `crypto` приходит аргументом. Тест — test/x25519.test.js.
 */
'use strict';

/**
 * Оболочка PKCS#8 для секретного ключа X25519. Отличается от Ed25519 ровно
 * одним байтом — идентификатором кривой (0x6e против 0x70). Перепутать их
 * означает получить стабильный, но чужой секрет, поэтому обе оболочки
 * проверяются тестом побайтно.
 */
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/** Оболочка SPKI для открытого ключа X25519. */
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

const KEY_LENGTH = 32;

/**
 * Известный ответ: RFC 7748, §6.1 — обмен Алисы и Боба.
 *
 * Взят из стандарта, а не посчитан нашим же кодом. То, что тот же ответ даёт
 * tweetnacl, закреплено отдельной проверкой в тесте.
 */
const VECTOR = {
  aliceSecret: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  alicePublic: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
  bobSecret: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
  bobPublic: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
  shared: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
};

/**
 * Точка малого порядка. Одна из шести известных — та, что проще всего
 * распознать глазом, и та, на которой ошибаются чаще всего.
 */
const LOW_ORDER_POINT = '0100000000000000000000000000000000000000000000000000000000000000';

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

/** Склеить оболочку и ключ. Копия, а не вид поверх чужой памяти. */
function wrap(prefix, key) {
  const out = new Uint8Array(prefix.length + KEY_LENGTH);
  out.set(prefix, 0);
  out.set(key.subarray(0, KEY_LENGTH), prefix.length);
  return out;
}

/**
 * Построить реализацию поверх Node-подобного `crypto`.
 *
 * Возвращает `{ sharedSecret }` либо null. Ничего не проверяет по существу —
 * это делает `selfTest`. Вырожденную точку НЕ обрабатывает: отказ OpenSSL
 * проходит наружу как есть, а приводит его к общему виду src/x25519.js.
 */
function createNativeX25519(nodeCrypto) {
  if (
    !nodeCrypto ||
    typeof nodeCrypto.createPrivateKey !== 'function' ||
    typeof nodeCrypto.createPublicKey !== 'function' ||
    typeof nodeCrypto.diffieHellman !== 'function'
  ) {
    return null;
  }

  return {
    sharedSecret(secretKey, publicKey) {
      const privateKey = nodeCrypto.createPrivateKey({
        key: wrap(PKCS8_PREFIX, secretKey),
        format: 'der',
        type: 'pkcs8',
      });
      const theirs = nodeCrypto.createPublicKey({
        key: wrap(SPKI_PREFIX, publicKey),
        format: 'der',
        type: 'spki',
      });
      const out = nodeCrypto.diffieHellman({ privateKey, publicKey: theirs });
      const copy = new Uint8Array(out.length);
      copy.set(out, 0);
      return copy;
    },
  };
}

/**
 * Проверить, что реализация делает ИМЕННО X25519 и отвергает вырожденную точку.
 *
 * Четыре проверки:
 *
 *   1. секрет совпал с вектором из RFC 7748 — кривая и порядок байтов те самые;
 *   2. обмен симметричен: у Алисы с ключом Боба и у Боба с ключом Алисы
 *      получается одно и то же (иначе перепутаны аргументы);
 *   3. секрет ЗАВИСИТ от секретки — другая секретка даёт другой ответ;
 *   4. точка малого порядка не даёт рабочего секрета.
 *
 * Четвёртая важнее прочих. Реализация, выдающая на такой точке рабочий на вид
 * секрет, позволяет подсунуть сообщение от поддельного ключа, и выглядит она
 * при этом совершенно исправной.
 *
 * Возвращает причину отказа строкой либо null.
 */
function selfTest(implementation) {
  if (!implementation) return 'нет реализации';

  const aliceSecret = fromHex(VECTOR.aliceSecret);
  const alicePublic = fromHex(VECTOR.alicePublic);
  const bobSecret = fromHex(VECTOR.bobSecret);
  const bobPublic = fromHex(VECTOR.bobPublic);

  const mine = implementation.sharedSecret(aliceSecret, bobPublic);
  if (!mine || mine.length !== KEY_LENGTH) return 'общий секрет не той длины';
  if (toHex(mine) !== VECTOR.shared) return 'общий секрет не совпал с вектором RFC 7748';

  const theirs = implementation.sharedSecret(bobSecret, alicePublic);
  if (toHex(theirs) !== VECTOR.shared) return 'обмен несимметричен — перепутаны аргументы';

  // Секрет обязан зависеть от секретки. Реализация, игнорирующая её, дала бы
  // одинаковый ответ обеим сторонам — и прошла бы обе проверки выше.
  const other = new Uint8Array(aliceSecret);
  other[0] ^= 0xff;
  let different;
  try {
    different = implementation.sharedSecret(other, bobPublic);
  } catch (error) {
    return `другая секретка уронила реализацию: ${(error && error.message) || error}`;
  }
  if (toHex(different) === VECTOR.shared) return 'общий секрет не зависит от секретки';

  // Главное. Отказ засчитывается в любом виде: бросок (OpenSSL) или нули
  // (tweetnacl). Не годится только рабочий на вид секрет.
  const lowOrder = fromHex(LOW_ORDER_POINT);
  let degenerate = null;
  try {
    degenerate = implementation.sharedSecret(aliceSecret, lowOrder);
  } catch (error) {
    degenerate = null; // отвергла броском — так и надо
  }
  if (degenerate) {
    let acc = 0;
    for (let i = 0; i < degenerate.length; i += 1) acc |= degenerate[i];
    if (acc !== 0) return 'точка малого порядка дала рабочий секрет';
  }

  return null;
}

/**
 * Найти реализацию и вернуть её, если она прошла самопроверку.
 *
 * Возвращает `{ implementation, reason }` — как у подписи.
 */
function resolveNativeX25519(load) {
  let nodeCrypto = null;
  try {
    nodeCrypto = typeof load === 'function' ? load() : null;
  } catch (error) {
    return { implementation: null, reason: `модуль не загрузился: ${(error && error.message) || error}` };
  }
  const implementation = createNativeX25519(nodeCrypto);
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
  VECTOR,
  LOW_ORDER_POINT,
  createNativeX25519,
  selfTest,
  resolveNativeX25519,
};
