const crypto = require('crypto');
const DEFAULT_WINDOW_MS = 20000;
const DEFAULT_MAX_PER_RECIPIENT = 5;
function chatNotificationTag(address, salt) {
  if (!address) return '';
  const hash = crypto.createHash('sha256').update('licno-chat-tag|' + String(address));
  if (salt) hash.update(salt);
  return hash
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .slice(0, 22);
}

function createPushGate({ windowMs = DEFAULT_WINDOW_MS, maxPerRecipient = DEFAULT_MAX_PER_RECIPIENT } = {}) {
  const lastByPair = new Map();
  const burstByRecipient = new Map();
  return {
    allow(to, chatTag, now) {
      if (!to) return false;
      const pairKey = to + '|' + (chatTag || '');
      if (now - (lastByPair.get(pairKey) || 0) < windowMs) return false;
      const burst = burstByRecipient.get(to);
      if (!burst || now - burst.start >= windowMs) {
        burstByRecipient.set(to, { start: now, count: 1 });
      } else {
        if (burst.count >= maxPerRecipient) return false;
        burst.count += 1;
      }
      lastByPair.set(pairKey, now);
      return true;
    },
    sweep(now) {
      const cutoff = now - 10 * windowMs;
      for (const [key, at] of lastByPair) if (at < cutoff) lastByPair.delete(key);
      for (const [key, burst] of burstByRecipient) if (burst.start < cutoff) burstByRecipient.delete(key);
    },
    size() {
      return lastByPair.size + burstByRecipient.size;
    },
  };
}
module.exports = {
  DEFAULT_WINDOW_MS,
  DEFAULT_MAX_PER_RECIPIENT,
  chatNotificationTag,
  createPushGate,
};