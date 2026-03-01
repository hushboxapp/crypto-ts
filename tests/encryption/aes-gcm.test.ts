import { describe, it, expect } from 'vitest';
import { AESGCMProvider } from '../../src/encryption/aes-gcm';
import { NativeProvider } from '../../src/randomness/native';

describe('AESGCMProvider', () => {
  const provider = new AESGCMProvider();
  const randomness = new NativeProvider();

  it('should encrypt and decrypt data correctly', async () => {
    const key = randomness.generate(32);
    const iv = randomness.generate(12);
    const data = new TextEncoder().encode('Hello, World!');

    const ciphertext = await provider.encrypt(data, key, iv);
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(ciphertext.length).toBeGreaterThan(0);

    const decrypted = await provider.decrypt(ciphertext, key, iv);
    expect(decrypted).toEqual(data);
    expect(new TextDecoder().decode(decrypted)).toBe('Hello, World!');
  });

  it('should throw DecryptionError for incorrect key', async () => {
    const key1 = randomness.generate(32);
    const key2 = randomness.generate(32);
    const iv = randomness.generate(12);
    const data = new TextEncoder().encode('Secret message');

    const ciphertext = await provider.encrypt(data, key1, iv);

    await expect(provider.decrypt(ciphertext, key2, iv)).rejects.toThrow();
  });

  it('should throw DecryptionError for incorrect IV', async () => {
    const key = randomness.generate(32);
    const iv1 = randomness.generate(12);
    const iv2 = randomness.generate(12);
    const data = new TextEncoder().encode('Secret message');

    const ciphertext = await provider.encrypt(data, key, iv1);

    await expect(provider.decrypt(ciphertext, key, iv2)).rejects.toThrow();
  });

  it('should throw EmptyKeyError for empty key', async () => {
    const key = new Uint8Array(0);
    const iv = randomness.generate(12);
    const data = new TextEncoder().encode('Hello');

    await expect(provider.encrypt(data, key, iv)).rejects.toThrow();
    await expect(provider.decrypt(data, key, iv)).rejects.toThrow();
  });

  it('should throw EmptyIVError for empty IV', async () => {
    const key = randomness.generate(32);
    const iv = new Uint8Array(0);
    const data = new TextEncoder().encode('Hello');

    await expect(provider.encrypt(data, key, iv)).rejects.toThrow();
    await expect(provider.decrypt(data, key, iv)).rejects.toThrow();
  });
});
