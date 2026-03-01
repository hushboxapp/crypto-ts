import { describe, it, expect, beforeAll } from 'vitest';
import { Key, EncryptedKey } from '../src/index';
import { HashingFactory } from '../src/hashing/hashing';
import { Argon2Provider } from '../src/hashing/argon2';

describe('Key', () => {
  beforeAll(() => {
    // Register Argon2 with low parameters for fast tests
    HashingFactory.addProvider(new Argon2Provider({
      iterations: 1,
      memorySize: 1024,
      parallelism: 1
    }));
  });

  it('should generate a random key', () => {
    const key = Key.generate();
    expect(key.material.length).toBe(32);
  });

  it('should encrypt and decrypt with a single password', async () => {
    const key = Key.generate();
    const password = 'my-password';
    
    const encryptedKey = await key.encrypt([password], 1);
    expect(encryptedKey.protectors.length).toBe(1);
    expect(encryptedKey.threshold).toBe(1);

    const decryptedKey = await encryptedKey.decrypt([password]);
    expect(decryptedKey.material).toEqual(key.material);
  });

  it('should encrypt and decrypt with M-of-N passwords', async () => {
    const key = Key.generate();
    const passwords = ['p1', 'p2', 'p3'];
    const threshold = 2;

    const encryptedKey = await key.encrypt(passwords, threshold);
    expect(encryptedKey.protectors.length).toBe(3);
    expect(encryptedKey.threshold).toBe(2);

    // Decrypt with exactly threshold passwords
    const decryptedKey = await encryptedKey.decrypt(['p1', 'p2']);
    expect(decryptedKey.material).toEqual(key.material);

    // Decrypt with different set of threshold passwords
    const decryptedKey2 = await encryptedKey.decrypt(['p2', 'p3']);
    expect(decryptedKey2.material).toEqual(key.material);

    // Decrypt with more than threshold passwords
    const decryptedKey3 = await encryptedKey.decrypt(['p1', 'p2', 'p3']);
    expect(decryptedKey3.material).toEqual(key.material);
  });

  it('should fail to decrypt with fewer than threshold passwords', async () => {
    const key = Key.generate();
    const passwords = ['p1', 'p2', 'p3'];
    const threshold = 2;

    const encryptedKey = await key.encrypt(passwords, threshold);

    await expect(encryptedKey.decrypt(['p1'])).rejects.toThrow();
    await expect(encryptedKey.decrypt(['wrong-password'])).rejects.toThrow();
  });

  it('should encode and decode EncryptedKey', async () => {
    const key = Key.generate();
    const encryptedKey = await key.encrypt(['password'], 1);
    
    const encoded = encryptedKey.encode();
    expect(typeof encoded).toBe('string');

    const decoded = EncryptedKey.decode(encoded);
    expect(decoded.threshold).toBe(encryptedKey.threshold);
    expect(decoded.encryptionProvider).toBe(encryptedKey.encryptionProvider);
    expect(decoded.sharingProvider).toBe(encryptedKey.sharingProvider);
    expect(decoded.protectors.length).toBe(encryptedKey.protectors.length);

    const decryptedKey = await decoded.decrypt(['password']);
    expect(decryptedKey.material).toEqual(key.material);
  });
});
