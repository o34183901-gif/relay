'use strict';
function createHttpRateLimit({ max, windowMs }) {
  const windows = new Map();
  function allow(key, now) {
    const k = key == null ? '' : String(key);
    const w = windows.get(k);
    if (!w || now - w.start >= windowMs) {
      windows.set(k, { start: now, count: 1 });
      sweep(now);
      return true;
    }
    w.count += 1;
    return w.count <= max;
  }
  function sweep(now) {
    if (windows.size < 4096) return;
    for (const [k, w] of windows) {
      if (now - w.start >= windowMs) windows.delete(k);
    }
  }
  function size() {
    return windows.size;
  }
  return { allow, size };
}
module.exports = { createHttpRateLimit };