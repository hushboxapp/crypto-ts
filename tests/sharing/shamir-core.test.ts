import { describe, it, expect } from 'vitest';
import { splitSecret, combineShares } from '../../src/sharing/shamir-core';

/**
 * Deterministic byte source for tests. Returns a sliced view of an internal
 * counter so calls do not need a live CSPRNG. The split path is independent
 * of the specific bytes chosen as long as they are well-formed.
 */
function makeCounter(): (n: number) => Uint8Array {
  let counter = 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = (counter++ & 0xff) || 1; // avoid 0 to keep coordinate uniqueness intuitive
    return out;
  };
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

describe('shamir-core', () => {
  it('round-trips a 32-byte secret with threshold-of-N', () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const shares = splitSecret(secret, 5, 3, randomBytes);
    expect(shares.length).toBe(5);
    expect(shares[0].length).toBe(33); // secret + x-coordinate

    const reconstructed = combineShares(shares.slice(0, 3));
    expect(reconstructed).toEqual(secret);
  });

  it('reconstructs from any subset of size >= threshold', () => {
    const secret = new TextEncoder().encode('the quick brown fox');
    const shares = splitSecret(secret, 5, 2, randomBytes);

    // Try several subsets of size threshold and a larger subset.
    const subsets = [
      [0, 1],
      [1, 3],
      [2, 4],
      [0, 2, 4],
    ];
    for (const idx of subsets) {
      const sub = idx.map((i) => shares[i]);
      expect(combineShares(sub)).toEqual(secret);
    }
  });

  it('returns wrong material when fewer than threshold shares are combined', () => {
    const secret = new TextEncoder().encode('the quick brown fox');
    const shares = splitSecret(secret, 5, 3, randomBytes);
    // With t=3, two shares are insufficient. Shamir doesn't detect this — it
    // just returns a wrong polynomial value. AES-GCM tag check upstream is
    // what actually rejects the bad reconstruction in real flows.
    const bogus = combineShares(shares.slice(0, 2));
    expect(bogus).not.toEqual(secret);
  });

  it('rejects duplicate x-coordinates on combine', () => {
    const secret = new TextEncoder().encode('payload');
    const shares = splitSecret(secret, 4, 2, randomBytes);
    // Force a duplicate x-coordinate by overwriting the last byte.
    shares[1][shares[1].length - 1] = shares[0][shares[0].length - 1];
    expect(() => combineShares([shares[0], shares[1]])).toThrow(/unique x-coordinates/);
  });

  it('rejects shares of differing length', () => {
    const secret = new TextEncoder().encode('payload');
    const shares = splitSecret(secret, 3, 2, randomBytes);
    const truncated = shares[1].slice(0, shares[1].length - 1);
    expect(() => combineShares([shares[0], truncated])).toThrow(/same byte length/);
  });

  it('rejects fewer than 2 shares on combine', () => {
    const secret = new TextEncoder().encode('payload');
    const shares = splitSecret(secret, 3, 2, randomBytes);
    expect(() => combineShares([shares[0]])).toThrow(/at least 2 shares/);
  });

  it('produces deterministic output for a fixed RNG', () => {
    // Two independent splits with the same byte source must produce identical
    // shares. Pins the public flow's reliance on the injected RNG and guards
    // against accidental nondeterminism inside the core.
    const secret = new TextEncoder().encode('deterministic');
    const a = splitSecret(secret, 3, 2, makeCounter());
    const b = splitSecret(secret, 3, 2, makeCounter());
    for (let i = 0; i < a.length; i++) {
      expect(b[i]).toEqual(a[i]);
    }
  });
});
