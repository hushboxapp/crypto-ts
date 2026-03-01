import { describe, it, expect } from 'vitest';
import { generateRandomBytes, encryptWithDEK, decryptWithDEK } from '../src/index';

describe('High-level Helpers', () => {
  it('should generate random bytes', () => {
    const bytes = generateRandomBytes(32);
    expect(bytes.length).toBe(32);
  });

  it('should encrypt and decrypt with DEK/KEK', async () => {
    const kek = generateRandomBytes(32);
    const data = new TextEncoder().encode('Sensitive data');

    const result = await encryptWithDEK(data, kek);
    expect(result.ciphertext).toBeInstanceOf(Uint8Array);
    expect(result.wrappedDEK).toBeInstanceOf(Uint8Array);
    expect(result.dataIV.length).toBe(12);
    expect(result.dekIV.length).toBe(12);

    const decrypted = await decryptWithDEK(
      result.ciphertext,
      result.wrappedDEK,
      kek,
      result.dataIV,
      result.dekIV
    );
    expect(decrypted).toEqual(data);
    expect(new TextDecoder().decode(decrypted)).toBe('Sensitive data');
  });
});
