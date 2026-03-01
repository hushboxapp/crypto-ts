import { describe, it, expect } from 'vitest';
import { AESGCMProvider } from '../../src/encryption/aes-gcm';

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

describe('AESGCMProvider - NIST Test Vectors', () => {
  const provider = new AESGCMProvider();

  // Vectors from NIST SP 800-38D, Appendix B
  const testVectors = [
    // AES-128
    {
      name: 'NIST AES-128 Case 1: Empty Plaintext',
      key: '00000000000000000000000000000000',
      iv: '000000000000000000000000',
      plaintext: '',
      ciphertext: '58e2fccefa7e3061367f1d57a4e7455a',
    },
    {
      name: 'NIST AES-128 Case 2: 128-bit Plaintext',
      key: '00000000000000000000000000000000',
      iv: '000000000000000000000000',
      plaintext: '00000000000000000000000000000000',
      ciphertext: '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf',
    },
    // AES-256
    {
      name: 'NIST AES-256 TC13: Empty Plaintext (GMAC mode)',
      key: '0000000000000000000000000000000000000000000000000000000000000000',
      iv: '000000000000000000000000',
      plaintext: '',
      ciphertext: '530f8afbc74536b9a963b4f1c4cb738b', // Just the tag
    },
    {
      name: 'NIST TC14: 128-bit Plaintext',
      key: '0000000000000000000000000000000000000000000000000000000000000000',
      iv: '000000000000000000000000',
      plaintext: '00000000000000000000000000000000',
      ciphertext: 'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919',
    },
    {
      name: 'NIST Reference: Non-zero inputs (No AAD)',
      key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
      iv: 'cafebabefacedbaddecaf888',
      plaintext:
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
      ciphertext:
        '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c',
    },
  ];

  testVectors.forEach((vector) => {
    it(`should match NIST vector: ${vector.name}`, async () => {
      const key = hexToBytes(vector.key);
      const iv = hexToBytes(vector.iv);
      const plaintext = hexToBytes(vector.plaintext);
      const expectedCiphertext = vector.ciphertext;

      // Test Encryption
      const actualCiphertext = await provider.encrypt(plaintext, key, iv);
      expect(bytesToHex(actualCiphertext)).toBe(expectedCiphertext);

      // Test Decryption
      const actualPlaintext = await provider.decrypt(actualCiphertext, key, iv);
      expect(bytesToHex(actualPlaintext)).toBe(vector.plaintext);
    });
  });
});
