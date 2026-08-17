'use strict';
const EVICT_HEADROOM = 0.01;

function evictionSize(count, max, headroom = EVICT_HEADROOM) {
  const have = Number(count);
  const limit = Number(max);
  if (!Number.isFinite(have) || !Number.isFinite(limit) || limit <= 0) return 0;
  if (have <= limit) return 0;
  const spare = Math.max(1, Math.floor(limit * headroom));
  return have - limit + spare;
}
module.exports = { EVICT_HEADROOM, evictionSize };