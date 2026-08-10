/* global importScripts, jsQR */
/**
 * QR распознаётся вне главного потока PWA. Особенно важно для Safari/iPhone:
 * jsQR на кадре камеры может считать сотни миллисекунд, но навигация и кнопка
 * «Отмена» всё это время должны оставаться отзывчивыми.
 */
importScripts('jsqr.bundle.js');

self.onmessage = (event) => {
  const input = event.data || {};
  try {
    const pixels = new Uint8ClampedArray(input.buffer);
    const decoded = jsQR(pixels, input.width, input.height, {
      inversionAttempts: 'attemptBoth',
    });
    self.postMessage({ id: input.id, data: decoded && decoded.data ? decoded.data : null });
  } catch (error) {
    self.postMessage({
      id: input.id,
      data: null,
      error: (error && error.message) || 'Не удалось распознать QR-код',
    });
  }
};
