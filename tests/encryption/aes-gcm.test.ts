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
    const { DecryptionError } = await import('../../src/errors');
    const key1 = randomness.generate(32);
    const key2 = randomness.generate(32);
    const iv = randomness.generate(12);
    const data = new TextEncoder().encode('Secret message');

    const ciphertext = await provider.encrypt(data, key1, iv);

    await expect(provider.decrypt(ciphertext, key2, iv)).rejects.toThrow(DecryptionError);
  });

  it('should throw DecryptionError for incorrect IV', async () => {
    const { DecryptionError } = await import('../../src/errors');
    const key = randomness.generate(32);
    const iv1 = randomness.generate(12);
    const iv2 = randomness.generate(12);
    const data = new TextEncoder().encode('Secret message');

    const ciphertext = await provider.encrypt(data, key, iv1);

    await expect(provider.decrypt(ciphertext, key, iv2)).rejects.toThrow(DecryptionError);
  });

  it('should throw EmptyKeyError for empty key', async () => {
    const { EmptyKeyError } = await import('../../src/errors');
    const key = new Uint8Array(0);
    const iv = randomness.generate(12);
    const data = new TextEncoder().encode('Hello');

    await expect(provider.encrypt(data, key, iv)).rejects.toThrow(EmptyKeyError);
    await expect(provider.decrypt(data, key, iv)).rejects.toThrow(EmptyKeyError);
  });

  it('should throw InvalidKeyError for incorrect key length', async () => {
    const { InvalidKeyError } = await import('../../src/errors');
    const iv = randomness.generate(12);
    const data = new TextEncoder().encode('Hello');

    const badLengths = [16, 24, 31, 33, 64];
    for (const len of badLengths) {
      const badKey = randomness.generate(len);
      await expect(provider.encrypt(data, badKey, iv)).rejects.toThrow(InvalidKeyError);
      await expect(provider.decrypt(data, badKey, iv)).rejects.toThrow(InvalidKeyError);
    }
  });

  it('should throw EmptyIVError for empty IV', async () => {
    const { EmptyIVError } = await import('../../src/errors');
    const key = randomness.generate(32);
    const iv = new Uint8Array(0);
    const data = new TextEncoder().encode('Hello');

    await expect(provider.encrypt(data, key, iv)).rejects.toThrow(EmptyIVError);
    await expect(provider.decrypt(data, key, iv)).rejects.toThrow(EmptyIVError);
  });
});
