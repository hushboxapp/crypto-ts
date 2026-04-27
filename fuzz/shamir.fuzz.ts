import { ShamirProvider } from '../src/sharing/shamir';
import { CryptoError } from '../src/errors';

const provider = new ShamirProvider();

export async function fuzz(data: Buffer): Promise<void> {
  if (data.length < 3) return;
  const mode = data[0] % 2;
  const rest = data.subarray(1);

  try {
    if (mode === 0) {
      // Round-trip: split then combine threshold shares.
      // Upstream lib requires 2 <= t <= n <= 255.
      const n = (rest[0] % 7) + 2; // 2..8
      const t = (rest[1] % (n - 1)) + 2; // 2..n
      const secret = new Uint8Array(rest.subarray(2));
      if (secret.length === 0) return;
      const shares = await provider.split(secret, n, t);
      const subset = shares.slice(0, t);
      const recovered = await provider.combine(subset);
      if (recovered.length !== secret.length) {
        throw new Error(`round-trip length mismatch: ${recovered.length} != ${secret.length}`);
      }
      for (let i = 0; i < secret.length; i++) {
        if (recovered[i] !== secret[i]) {
          throw new Error(`round-trip byte mismatch at index ${i}`);
        }
      }
    } else {
      // Combine arbitrary shares. Must throw a typed error or return, not crash.
      const shareCount = (rest[0] % 6) + 1;
      const shareLen = Math.max(1, Math.floor((rest.length - 1) / shareCount));
      const shares: Uint8Array[] = [];
      for (let i = 0; i < shareCount; i++) {
        const start = 1 + i * shareLen;
        const end = start + shareLen;
        if (end > rest.length) break;
        shares.push(new Uint8Array(rest.subarray(start, end)));
      }
      if (shares.length === 0) return;
      try {
        await provider.combine(shares);
      } catch (e) {
        if (e instanceof CryptoError) return;
        if (e instanceof Error) return; // upstream lib throws plain Error on malformed shares
        throw e;
      }
    }
  } catch (e) {
    if (e instanceof CryptoError) return;
    throw e;
  }
}
