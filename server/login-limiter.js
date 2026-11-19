const windowMs = 60_000;
const maxAttemptsPerPeer = 8;
const maxAttempts = 30;
const maxConcurrent = 2;

export function createLoginLimiter(now = () => performance.now()) {
  const attemptsByPeer = new Map();
  let expiresAt = 0;
  let attempts = 0;
  let active = 0;

  return {
    acquire(peer) {
      const time = now();
      if (time >= expiresAt) {
        attemptsByPeer.clear();
        attempts = 0;
        expiresAt = time + windowMs;
      }
      const peerAttempts = attemptsByPeer.get(peer) ?? 0;
      if (peerAttempts >= maxAttemptsPerPeer || attempts >= maxAttempts) {
        return Math.ceil((expiresAt - time) / 1_000);
      }
      // Reject immediately instead of queuing expensive work in libuv.
      if (active >= maxConcurrent) return 1;
      attemptsByPeer.set(peer, peerAttempts + 1);
      attempts++;
      active++;
      return 0;
    },
    release() {
      active--;
    },
  };
}
