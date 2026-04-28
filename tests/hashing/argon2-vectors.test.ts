import { describe, it, expect } from 'vitest';
import { Argon2Provider } from '../../src/hashing/argon2';

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('Argon2Provider - Argon2id Test Vectors', () => {
  it('should be consistent for the same inputs', async () => {
    const provider = new Argon2Provider({
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 32
    });
    const password = 'password';
    const salt = hexToBytes('02020202020202020202020202020202');

    const key1 = await provider.derive(password, salt);
    const key2 = await provider.derive(password, salt);
    expect(bytesToHex(key1)).toBe(bytesToHex(key2));
  });

  /**
   * Standard Argon2id Vector (p=1)
   * Password: "password"
   * Salt: "somesalt"
   * p=1, m=256, t=2
   */
  it('should match Argon2id test vector (p=1, m=256, t=2)', async () => {
    const password = 'password';
    const salt = new TextEncoder().encode('somesalt');

    const options = {
      iterations: 2,
      memorySize: 256,
      parallelism: 1,
      hashLength: 32,
    };

    const provider = new Argon2Provider(options);
    const key = await provider.derive(password, salt);

    // Expected output for Argon2id, v=13, t=2, m=256, p=1, salt="somesalt", pwd="password"
    const expectedKey = '9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe';
    expect(bytesToHex(key)).toBe(expectedKey);
  });

  it('should produce different output for different salts', async () => {
    const provider = new Argon2Provider({
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 32,
    });
    const password = 'password';
    const a = await provider.derive(password, hexToBytes('02020202020202020202020202020202'));
    const b = await provider.derive(password, hexToBytes('03030303030303030303030303030303'));
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it('should produce different output for different passwords', async () => {
    const provider = new Argon2Provider({
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 32,
    });
    const salt = hexToBytes('02020202020202020202020202020202');
    const a = await provider.derive('password-a', salt);
    const b = await provider.derive('password-b', salt);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it('should respect hashLength', async () => {
    const salt = hexToBytes('02020202020202020202020202020202');
    const short = new Argon2Provider({
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 16,
    });
    const long = new Argon2Provider({
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 64,
    });
    expect((await short.derive('p', salt)).length).toBe(16);
    expect((await long.derive('p', salt)).length).toBe(64);
  });

  it('should produce different output when iterations differ', async () => {
    const salt = hexToBytes('02020202020202020202020202020202');
    const t1 = new Argon2Provider({
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 32,
    });
    const t2 = new Argon2Provider({
      iterations: 2,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 32,
    });
    const a = await t1.derive('p', salt);
    const b = await t2.derive('p', salt);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});
