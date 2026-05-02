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

  it('should refuse encrypt/decrypt with a disposed Key', async () => {
    const { KeyDisposedError } = await import('../src/errors');
    const key = Key.generate();
    const data = new TextEncoder().encode('payload');
    const doc = await Document.encrypt(data, key);

    key.dispose();
    await expect(Document.encrypt(data, key)).rejects.toThrow(KeyDisposedError);
    await expect(doc.decrypt(key)).rejects.toThrow(KeyDisposedError);
  });

  it('should still accept legacy string-form encodingProvider argument', async () => {
    const key = Key.generate();
    const data = new TextEncoder().encode('payload');
    const doc = await Document.encrypt(data, key);
    const decoded = Document.decode(doc.encode(), 'base64');
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

    // Widen the algorithm allowlist so the decoder accepts the alias and we
    // exercise the AAD-mismatch path rather than the allowlist guard.
    const tamperedDoc = Document.decode(tampered, {
      allowedAlgorithms: ['aes-gcm', 'aes-gcm-alias'],
    });
    await expect(tamperedDoc.decrypt(key)).rejects.toThrow(DecryptionError);
  });

  it('should reject decode when algorithm is not on the allowlist', async () => {
    const { DisallowedProviderError } = await import('../src/errors');
    const key = Key.generate();
    const data = new TextEncoder().encode('payload');
    const doc = await Document.encrypt(data, key);

    const json = JSON.parse(atob(doc.encode()));
    json.m.a = 'rot13';
    const tampered = btoa(JSON.stringify(json));

    expect(() => Document.decode(tampered)).toThrow(DisallowedProviderError);
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

  it('should throw InvalidFormatError for valid base64 but invalid JSON in decode', async () => {
    const { InvalidFormatError } = await import('../src/errors');
    const encoded = btoa('not json');
    expect(() => Document.decode(encoded)).toThrow(InvalidFormatError);
  });

  it('should throw InvalidFormatError when envelope is not an object', async () => {
    const { InvalidFormatError } = await import('../src/errors');
    expect(() => Document.decode(btoa('null'))).toThrow(InvalidFormatError);
    expect(() => Document.decode(btoa('[]'))).toThrow(InvalidFormatError);
    expect(() => Document.decode(btoa('"string"'))).toThrow(InvalidFormatError);
  });

  it('should throw InvalidFormatError when required fields are missing', async () => {
    const { InvalidFormatError } = await import('../src/errors');
    const missingC = btoa(JSON.stringify({ v: 2, m: { i: 'aXY=', a: 'aes-gcm' } }));
    const missingM = btoa(JSON.stringify({ v: 2, c: 'Y2lw' }));
    const missingMA = btoa(JSON.stringify({ v: 2, c: 'Y2lw', m: { i: 'aXY=' } }));
    expect(() => Document.decode(missingC)).toThrow(InvalidFormatError);
    expect(() => Document.decode(missingM)).toThrow(InvalidFormatError);
    expect(() => Document.decode(missingMA)).toThrow(InvalidFormatError);
  });

  it('should throw InvalidFormatError when metadata is not an object', async () => {
    const { InvalidFormatError } = await import('../src/errors');
    const badM = btoa(JSON.stringify({ v: 2, c: 'Y2lw', m: 'not-an-object' }));
    const nullM = btoa(JSON.stringify({ v: 2, c: 'Y2lw', m: null }));
    expect(() => Document.decode(badM)).toThrow(InvalidFormatError);
    expect(() => Document.decode(nullM)).toThrow(InvalidFormatError);
  });
});
