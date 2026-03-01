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

  it('should throw error for empty data', async () => {
    const key = Key.generate();
    await expect(Document.encrypt(new Uint8Array(0), key)).rejects.toThrow();
  });
});
