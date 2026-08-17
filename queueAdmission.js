'use strict';
const QUEUE_RESERVE = 100;
function admitEnvelope({
  recipientCount = 0,
  strangerCount = 0,
  senderCount = 0,
  correspondent = false,
  senderKnown = true,
  maxPerUser = 0,
  maxPerSender = 0,
  reserve = QUEUE_RESERVE,
} = {}) {
  if (maxPerSender && senderKnown && senderCount >= maxPerSender) {
    return { admit: true, evict: 'own' };
  }
  if (!maxPerUser || recipientCount < maxPerUser) {
    if (
      maxPerUser > 0 &&
      reserve > 0 &&
      senderKnown &&
      !correspondent &&
      strangerCount >= Math.max(0, maxPerUser - reserve)
    ) {
      return { admit: false, evict: null };
    }
    return { admit: true, evict: null };
  }
  if (!senderKnown) {
    return { admit: true, evict: 'oldest' };
  }
  if (senderCount > 0) {
    return { admit: true, evict: 'own' };
  }
  if (correspondent && strangerCount > 0) {
    return { admit: true, evict: 'stranger' };
  }
  return { admit: false, evict: null };
}
module.exports = {
  QUEUE_RESERVE,
  admitEnvelope,
};