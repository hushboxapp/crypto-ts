import { describe, it, expect } from 'vitest';
import { Document, Key } from '../src/index';

describe('Document', () => {
  it('should encrypt and decrypt data with a Key', async () => {
    const key = Key.generate();
    const data = new TextEncoder().encode('Sensitive information');

    const doc = await Document.encrypt(data, key);
    expect(doc.ciphertext).toBeInstanceOf(Uint8Array);
    expect(doc.metadata.algorithm).toBe('aes-gcm');

    const decrypted = await doc.decrypt(key);
    expect(decrypted).toEqual(data);
    expect(new TextDecoder().decode(decrypted)).toBe('Sensitive information');
  });

  it('should encode and decode Document', async () => {
    const key = Key.generate();
    const data = new TextEncoder().encode('Sensitive information');
    const doc = await Document.encrypt(data, key);

    const encoded = doc.encode();
    expect(typeof encoded).toBe('string');

    const decoded = Document.decode(encoded);
    expect(decoded.metadata.algorithm).toBe(doc.metadata.algorithm);
    expect(decoded.metadata.iv).toEqual(doc.metadata.iv);
    expect(decoded.ciphertext).toEqual(doc.ciphertext);

    const decrypted = await decoded.decrypt(key);
    expect(decrypted).toEqual(data);
  });

  it('should throw EmptyDataError for empty data', async () => {
    const { EmptyDataError } = await import('../src/errors');
    const key = Key.generate();
    await expect(Document.encrypt(new Uint8Array(0), key)).rejects.toThrow(EmptyDataError);
  });

  it('should reject decryption when version is tampered with', async () => {
    const { DecryptionError } = await import('../src/errors');
    const key = Key.generate();
    const data = new TextEncoder().encode('payload');
    const doc = await Document.encrypt(data, key);

    // Decode the envelope, flip the version, re-encode. AAD is bound to the
    // original version, so the rewritten v1 envelope must fail to decrypt.
    const encoded = doc.encode();
    const json = JSON.parse(atob(encoded));
    json.v = 1;
    const tampered = btoa(JSON.stringify(json));

    const tamperedDoc = Document.decode(tampered);
    await expect(tamperedDoc.decrypt(key)).rejects.toThrow(DecryptionError);
  });

  it('should reject decryption when algorithm name is tampered with', async () => {
    const { DecryptionError } = await import('../src/errors');
    const key = Key.generate();
    const data = new TextEncoder().encode('payload');
    const doc = await Document.encrypt(data, key);

    // Forge the algorithm string. Lookup will succeed (still 'aes-gcm' in the
    // factory under a different key), so we register an alias to exercise the
    // AAD mismatch path purely.
    const { EncryptionFactory } = await import('../src/encryption/encryption');
    const { AESGCMProvider } = await import('../src/encryption/aes-gcm');
    const aliased = new AESGCMProvider();
    Object.defineProperty(aliased, 'name', { value: 'aes-gcm-alias' });
    EncryptionFactory.addProvider(aliased);

    const json = JSON.parse(atob(doc.encode()));
    json.m.a = 'aes-gcm-alias';
    const tampered = btoa(JSON.stringify(json));

    const tamperedDoc = Document.decode(tampered);
    await expect(tamperedDoc.decrypt(key)).rejects.toThrow(DecryptionError);
  });

  it('should decode legacy v1 documents (no AAD) and decrypt them', async () => {
    // Build a v1 envelope by hand: encrypt without AAD, wrap with v:1.
    const { AESGCMProvider } = await import('../src/encryption/aes-gcm');
    const { Base64Engine } = await import('../src/encoding/base64');
    const aes = new AESGCMProvider();
    const enc = new Base64Engine();

    const key = Key.generate();
    const iv = new Uint8Array(12).fill(3);
    const data = new TextEncoder().encode('legacy payload');
    const ciphertext = await aes.encrypt(data, key.material, iv); // no AAD

    const v1Blob = {
      v: 1,
      c: enc.encode(ciphertext),
      m: { i: enc.encode(iv), a: 'aes-gcm' },
    };
    const encoded = enc.btoa(JSON.stringify(v1Blob));

    const decoded = Document.decode(encoded);
    expect(decoded.version).toBe(1);
    const plaintext = await decoded.decrypt(key);
    expect(plaintext).toEqual(data);
  });

  it('should throw UnsupportedVersionError for incorrect version in decode', async () => {
    const { UnsupportedVersionError } = await import('../src/errors');
    const data = {
      v: 99, // Unsupported version
      c: 'Y2lwaGVydGV4dA==',
      m: {
        i: 'aXY=',
        a: 'aes-gcm',
      },
    };
    const encoded = btoa(JSON.stringify(data));
    expect(() => Document.decode(encoded)).toThrow(UnsupportedVersionError);
  });
});
