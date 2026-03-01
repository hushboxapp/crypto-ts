import { EncryptionProvider, EncryptionFactory } from './encryption';
import {
  SecureContextError,
  DecryptionError,
  CryptoApiUnavailableError,
  EmptyDataError,
  EmptyKeyError,
  EmptyIVError,
} from '../errors';

/**
 * The standard length for an AES-GCM initialization vector (96 bits).
 * 12 bytes is the NIST-recommended size for GCM to avoid the overhead of hashing the IV.
 */
export const AES_GCM_IV_LENGTH = 12;

/**
 * The standard length for an AES-256 key (256 bits).
 */
export const AES_GCM_KEY_LENGTH = 32;

/**
 * An implementation of EncryptionProvider using the AES-GCM algorithm via Web Crypto API.
 * AES-GCM provides both confidentiality and data integrity (authenticated encryption).
 */
export class AESGCMProvider implements EncryptionProvider {
  /** The unique identifier for this provider. */
  readonly name = 'aes-gcm';

  /**
   * Internal helper to access the SubtleCrypto API.
   * Checks for Secure Context and API availability.
   * @throws {SecureContextError} If running in an insecure context.
   * @throws {CryptoApiUnavailableError} If Web Crypto is not supported.
   */
  private getSubtleCrypto(): SubtleCrypto {
    if (
      typeof globalThis !== 'undefined' &&
      'isSecureContext' in globalThis &&
      !globalThis.isSecureContext
    ) {
      throw new SecureContextError();
    }

    if (typeof window !== 'undefined' && window.crypto) {
      return window.crypto.subtle;
    }
    // @ts-ignore
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
      // @ts-ignore
      return globalThis.crypto.subtle;
    }
    throw new CryptoApiUnavailableError();
  }

  /**
   * Encrypts data using AES-GCM.
   * @param data - Raw data to encrypt.
   * @param key - 256-bit symmetric key.
   * @param iv - 12-byte initialization vector.
   * @returns Promise resolving to ciphertext + auth tag.
   * @throws {EmptyDataError} If data is empty.
   * @throws {EmptyKeyError} If key is empty.
   * @throws {EmptyIVError} If IV is empty.
   */
  async encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    if (key.length === 0) throw new EmptyKeyError();
    if (iv.length === 0) throw new EmptyIVError();

    const crypto = this.getSubtleCrypto();
    const aesKey = await crypto.importKey('raw', key as BufferSource, 'AES-GCM', false, [
      'encrypt',
    ]);

    const encrypted = await crypto.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      aesKey,
      data as BufferSource,
    );

    return new Uint8Array(encrypted);
  }

  /**
   * Decrypts ciphertext using AES-GCM.
   * @param ciphertext - Encrypted data + auth tag.
   * @param key - 256-bit symmetric key.
   * @param iv - 12-byte initialization vector.
   * @returns Promise resolving to original plaintext.
   * @throws {EmptyDataError} If ciphertext is empty.
   * @throws {EmptyKeyError} If key is empty.
   * @throws {EmptyIVError} If IV is empty.
   * @throws {DecryptionError} If decryption or authentication fails.
   */
  async decrypt(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    if (key.length === 0) throw new EmptyKeyError();
    if (iv.length === 0) throw new EmptyIVError();

    const crypto = this.getSubtleCrypto();
    const aesKey = await crypto.importKey('raw', key as BufferSource, 'AES-GCM', false, [
      'decrypt',
    ]);

    const decrypted = await crypto
      .decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, aesKey, ciphertext as BufferSource)
      .catch(() => {
        throw new DecryptionError();
      });

    return new Uint8Array(decrypted);
  }
}

// Automatically register the provider upon module import.
EncryptionFactory.addProvider(new AESGCMProvider());
