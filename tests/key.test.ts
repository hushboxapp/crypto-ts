import { describe, it, expect, beforeAll, vi } from 'vitest';
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
    const { InsufficientSharesError } = await import('../src/errors');
    const key = Key.generate();
    const passwords = ['p1', 'p2', 'p3'];
    const threshold = 2;

    const encryptedKey = await key.encrypt(passwords, threshold);

    // One correct password is not enough for threshold 2
    await expect(encryptedKey.decrypt(['p1'])).rejects.toThrow(InsufficientSharesError);
    // Incorrect passwords should also fail
    await expect(encryptedKey.decrypt(['wrong-password'])).rejects.toThrow(InsufficientSharesError);
    // Two incorrect passwords should also fail
    await expect(encryptedKey.decrypt(['wrong1', 'wrong2'])).rejects.toThrow(InsufficientSharesError);
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

  it('should throw EmptyKeyError for empty material', async () => {
    const { EmptyKeyError } = await import('../src/errors');
    expect(() => new Key(new Uint8Array(0))).toThrow(EmptyKeyError);
  });

  it('should throw InvalidKeyError for incorrect material length', async () => {
    const { InvalidKeyError } = await import('../src/errors');
    expect(() => new Key(new Uint8Array(31))).toThrow(InvalidKeyError);
    expect(() => new Key(new Uint8Array(33))).toThrow(InvalidKeyError);
  });

  it('should reject decryption when threshold is tampered with', async () => {
    const { InsufficientSharesError } = await import('../src/errors');
    const key = Key.generate();
    const encryptedKey = await key.encrypt(['p1', 'p2', 'p3'], 2);

    const json = JSON.parse(atob(encryptedKey.encode()));
    json.t = 1; // Forge threshold downgrade.
    const tampered = btoa(JSON.stringify(json));

    const decoded = EncryptedKey.decode(tampered);
    // Every protector now fails AAD check; no shares unlock; insufficient.
    await expect(decoded.decrypt(['p1'])).rejects.toThrow(InsufficientSharesError);
  });

  it('should reject decryption when hashing params are downgraded', async () => {
    const { InsufficientSharesError } = await import('../src/errors');
    const key = Key.generate();
    const encryptedKey = await key.encrypt(['p1'], 1);

    const json = JSON.parse(atob(encryptedKey.encode()));
    json.p[0].h = { iterations: 1, memorySize: 8, parallelism: 1, hashLength: 32 };
    const tampered = btoa(JSON.stringify(json));

    const decoded = EncryptedKey.decode(tampered);
    // Even though the wrong params would still decrypt under v2, v3 binds
    // them via AAD: tampered params yield an authentication failure.
    await expect(decoded.decrypt(['p1'])).rejects.toThrow(InsufficientSharesError);
  });

  it('should decode legacy v1 keys and decrypt them', async () => {
    // v1 keys did not persist hashing params; the decoder must fall back to the
    // frozen v1 defaults. We construct a v1 blob by hand here to lock in compat.
    const password = 'legacy-password';
    const salt = new Uint8Array(16).fill(7);
    const iv = new Uint8Array(12).fill(9);
    const material = new Uint8Array(32).fill(42);

    const v1Provider = new Argon2Provider({
      iterations: 2,
      memorySize: 65536,
      parallelism: 1,
      hashLength: 32,
    });
    const passwordKey = await v1Provider.derive(password, salt);

    const { AESGCMProvider } = await import('../src/encryption/aes-gcm');
    const aes = new AESGCMProvider();
    const ciphertext = await aes.encrypt(material, passwordKey, iv);

    const encoder = (await import('../src/encoding/base64')).Base64Engine;
    const enc = new encoder();
    const v1Blob = {
      v: 1,
      t: 1,
      e: 'aes-gcm',
      s: 'shamir',
      p: [
        {
          s: enc.encode(salt),
          i: enc.encode(iv),
          c: enc.encode(ciphertext),
          a: 'argon2id',
        },
      ],
    };
    const encoded = enc.btoa(JSON.stringify(v1Blob));

    const decoded = EncryptedKey.decode(encoded);
    const decrypted = await decoded.decrypt([password]);
    expect(decrypted.material).toEqual(material);
  }, 20000);

  it('should throw UnsupportedVersionError for incorrect version in decode', async () => {
    const { UnsupportedVersionError } = await import('../src/errors');
    const data = {
      v: 99, // Unsupported version
      t: 1,
      e: 'aes-gcm',
      s: 'shamir',
      p: [],
    };
    const encoded = btoa(JSON.stringify(data));
    expect(() => EncryptedKey.decode(encoded)).toThrow(UnsupportedVersionError);
  });

  it('should throw EmptyPasswordsError for empty passwords in encrypt', async () => {
    const { EmptyPasswordsError } = await import('../src/errors');
    const key = Key.generate();
    await expect(key.encrypt([], 1)).rejects.toThrow(EmptyPasswordsError);
  });

  it('should throw InvalidThresholdError for invalid threshold', async () => {
    const { InvalidThresholdError } = await import('../src/errors');
    const key = Key.generate();
    await expect(key.encrypt(['p1'], 2)).rejects.toThrow(InvalidThresholdError);
    await expect(key.encrypt(['p1'], 0)).rejects.toThrow(InvalidThresholdError);
  });

  it('should zero key material on dispose() and refuse use afterwards', async () => {
    const { KeyDisposedError } = await import('../src/errors');
    const key = Key.generate();
    expect(key.disposed).toBe(false);
    expect(key.material.some((b) => b !== 0)).toBe(true);

    key.dispose();
    expect(key.disposed).toBe(true);
    expect(key.material.every((b) => b === 0)).toBe(true);

    await expect(key.encrypt(['p'], 1)).rejects.toThrow(KeyDisposedError);
    // Idempotent: a second dispose() is a no-op.
    key.dispose();
  });

  it('should reject EncryptedKey.decode when encryption provider not allowlisted', async () => {
    const { DisallowedProviderError } = await import('../src/errors');
    const key = Key.generate();
    const enc = await key.encrypt(['p'], 1);
    const json = JSON.parse(atob(enc.encode()));
    json.e = 'rot13';
    const tampered = btoa(JSON.stringify(json));
    expect(() => EncryptedKey.decode(tampered)).toThrow(DisallowedProviderError);
  });

  it('should reject EncryptedKey.decode when sharing provider not allowlisted', async () => {
    const { DisallowedProviderError } = await import('../src/errors');
    const key = Key.generate();
    const enc = await key.encrypt(['p'], 1);
    const json = JSON.parse(atob(enc.encode()));
    json.s = 'unknown-sss';
    const tampered = btoa(JSON.stringify(json));
    expect(() => EncryptedKey.decode(tampered)).toThrow(DisallowedProviderError);
  });

  it('should reject EncryptedKey.decode when hashing provider not allowlisted', async () => {
    const { DisallowedProviderError } = await import('../src/errors');
    const key = Key.generate();
    const enc = await key.encrypt(['p'], 1);
    const json = JSON.parse(atob(enc.encode()));
    json.p[0].a = 'md5';
    const tampered = btoa(JSON.stringify(json));
    expect(() => EncryptedKey.decode(tampered)).toThrow(DisallowedProviderError);
  });

  it('should accept widened allowlist for custom providers', async () => {
    const key = Key.generate();
    const enc = await key.encrypt(['p'], 1);
    const decoded = EncryptedKey.decode(enc.encode(), {
      allowed: { encryption: ['aes-gcm'], sharing: ['shamir'], hashing: ['argon2id'] },
    });
    const restored = await decoded.decrypt(['p']);
    expect(restored.material).toEqual(key.material);
  });

  it('should still accept legacy string-form encodingProvider argument', async () => {
    const key = Key.generate();
    const enc = await key.encrypt(['p'], 1);
    const decoded = EncryptedKey.decode(enc.encode(), 'base64');
    const restored = await decoded.decrypt(['p']);
    expect(restored.material).toEqual(key.material);
  });

  it('should throw EmptyPasswordsError for empty passwords in decrypt', async () => {
    const { EmptyPasswordsError } = await import('../src/errors');
    const key = Key.generate();
    const encryptedKey = await key.encrypt(['p1'], 1);
    await expect(encryptedKey.decrypt([])).rejects.toThrow(EmptyPasswordsError);
  });

  it('should not re-derive against already-unlocked protectors', async () => {
    // The decrypt loop tracks unlocked protector indices so each protector is
    // probed at most once per decrypt call. For 3-of-3 the previous behavior
    // was 1+2+3 = 6 derivations; with tracking it should be exactly 3.
    const provider = HashingFactory.getProvider('argon2id');
    const key = Key.generate();
    const encryptedKey = await key.encrypt(['pA', 'pB', 'pC'], 3);

    const spy = vi.spyOn(provider, 'derive');
    try {
      const restored = await encryptedKey.decrypt(['pA', 'pB', 'pC']);
      expect(restored.material).toEqual(key.material);
      expect(spy).toHaveBeenCalledTimes(3);
    } finally {
      spy.mockRestore();
    }
  });
});
