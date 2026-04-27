import {
  AESGCMProvider,
  AES_GCM_IV_LENGTH,
  AES_GCM_KEY_LENGTH,
} from '../src/encryption/aes-gcm';
import { CryptoError, DecryptionError } from '../src/errors';

const provider = new AESGCMProvider();

export async function fuzz(data: Buffer): Promise<void> {
  if (data.length < 1) return;
  const mode = data[0] % 3;
  const rest = data.subarray(1);

  try {
    switch (mode) {
      case 0: {
        // Round-trip: derive key + iv from input, encrypt then decrypt.
        if (rest.length < AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH) return;
        const key = new Uint8Array(rest.subarray(0, AES_GCM_KEY_LENGTH));
        const iv = new Uint8Array(
          rest.subarray(AES_GCM_KEY_LENGTH, AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH),
        );
        const plaintext = new Uint8Array(rest.subarray(AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH));
        const ct = await provider.encrypt(plaintext, key, iv);
        const pt = await provider.decrypt(ct, key, iv);
        if (pt.length !== plaintext.length) {
          throw new Error(`round-trip length mismatch: ${pt.length} != ${plaintext.length}`);
        }
        for (let i = 0; i < plaintext.length; i++) {
          if (pt[i] !== plaintext[i]) {
            throw new Error(`round-trip byte mismatch at index ${i}`);
          }
        }
        break;
      }
      case 1: {
        // Tamper detection: encrypt, flip a byte, expect DecryptionError.
        if (rest.length < AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH + 1) return;
        const key = new Uint8Array(rest.subarray(0, AES_GCM_KEY_LENGTH));
        const iv = new Uint8Array(
          rest.subarray(AES_GCM_KEY_LENGTH, AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH),
        );
        const plaintext = new Uint8Array(rest.subarray(AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH));
        const ct = await provider.encrypt(plaintext, key, iv);
        if (ct.length === 0) return;
        const tampered = new Uint8Array(ct);
        tampered[0] ^= 0x01;
        try {
          await provider.decrypt(tampered, key, iv);
          throw new Error('tampered ciphertext decrypted without error');
        } catch (e) {
          if (e instanceof DecryptionError) return;
          throw e;
        }
      }
      case 2: {
        // Decrypt arbitrary input. Must throw DecryptionError, not crash.
        if (rest.length < AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH) return;
        const key = new Uint8Array(rest.subarray(0, AES_GCM_KEY_LENGTH));
        const iv = new Uint8Array(
          rest.subarray(AES_GCM_KEY_LENGTH, AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH),
        );
        const ciphertext = new Uint8Array(rest.subarray(AES_GCM_KEY_LENGTH + AES_GCM_IV_LENGTH));
        try {
          await provider.decrypt(ciphertext, key, iv);
        } catch (e) {
          if (e instanceof DecryptionError) return;
          throw e;
        }
        break;
      }
    }
  } catch (e) {
    if (e instanceof CryptoError) return;
    throw e;
  }
}
