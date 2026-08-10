/* global importScripts, nacl */
/**
 * Расшифровка вложений в отдельном потоке (веб-версия).
 *
 * Зачем: тело вложения расшифровывается secretbox'ом на чистом JS. Для кружка
 * или видео в несколько мегабайт это сотни миллисекунд сплошного счёта, и в
 * главном потоке они означают замерший интерфейс — не нажать «назад», не
 * набрать сообщение. Здесь тот же счёт идёт параллельно, а UI остаётся живым.
 *
 * Формат .enc-файла (общий с Android): utf8-текст, внутри base64(nonce||cipher).
 * Поэтому на вход приходит сырой буфер файла, а не готовая base64-строка:
 * перекодировка тоже стоит времени и ей здесь самое место.
 */
importScripts('nacl-fast.min.js');

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

self.onmessage = (event) => {
  const data = event.data || {};
  const id = data.id;
  try {
    // Файл хранится как utf8-текст с base64 внутри — разворачиваем оба слоя.
    const packedB64 = new TextDecoder().decode(new Uint8Array(data.packedBuffer));
    const packed = base64ToBytes(packedB64.trim());
    const key = new Uint8Array(data.keyBuffer);
    const nonceLength = nacl.secretbox.nonceLength;
    if (packed.length <= nonceLength) {
      self.postMessage({ id, plainBuffer: null });
      return;
    }
    // subarray, а не slice: срез без копирования лишнего мегабайта на видео.
    const plain = nacl.secretbox.open(
      packed.subarray(nonceLength),
      packed.subarray(0, nonceLength),
      key
    );
    if (!plain) {
      // Ключ не подошёл или файл повреждён — это не ошибка воркера, а обычный
      // отрицательный результат: экран покажет вложение как недоступное.
      self.postMessage({ id, plainBuffer: null });
      return;
    }
    const plainBuffer = plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength);
    self.postMessage({ id, plainBuffer }, [plainBuffer]);
  } catch (error) {
    self.postMessage({
      id,
      error: (error && error.message) || 'Не удалось расшифровать вложение',
    });
  }
};
