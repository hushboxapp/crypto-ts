import { EncryptionProvider, EncryptionFactory } from './encryption';
import {
  SecureContextError,
  DecryptionError,
  CryptoApiUnavailableError,
  EmptyKeyError,
  EmptyIVError,
  InvalidKeyError,
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
    if (globalThis.isSecureContext === false) {
      throw new SecureContextError();
    }
    if (!globalThis.crypto?.subtle) {
      throw new CryptoApiUnavailableError();
    }
    return globalThis.crypto.subtle;
  }

  /**
   * Encrypts data using AES-GCM.
   * @param data - Raw data to encrypt.
   * @param key - 256-bit symmetric key.
   * @param iv - 12-byte initialization vector.
   * @param aad - Optional Additional Authenticated Data bound into the auth tag.
   * @returns Promise resolving to ciphertext + auth tag.
   * @throws {EmptyKeyError} If key is empty.
   * @throws {EmptyIVError} If IV is empty.
   */
  async encrypt(
    data: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    if (key.length === 0) throw new EmptyKeyError();
    if (key.length !== AES_GCM_KEY_LENGTH) throw new InvalidKeyError();
    if (iv.length === 0) throw new EmptyIVError();

    const crypto = this.getSubtleCrypto();
    const aesKey = await crypto.importKey('raw', key as BufferSource, 'AES-GCM', false, [
      'encrypt',
    ]);

    const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
    if (aad && aad.length > 0) params.additionalData = aad as BufferSource;

    const encrypted = await crypto.encrypt(params, aesKey, data as BufferSource);

    return new Uint8Array(encrypted);
  }

  /**
   * Decrypts ciphertext using AES-GCM.
   * @param ciphertext - Encrypted data + auth tag.
   * @param key - 256-bit symmetric key.
   * @param iv - 12-byte initialization vector.
   * @param aad - Optional Additional Authenticated Data. Must match the value supplied at encrypt time.
   * @returns Promise resolving to original plaintext.
   * @throws {EmptyKeyError} If key is empty.
   * @throws {EmptyIVError} If IV is empty.
   * @throws {DecryptionError} If decryption or authentication fails.
   */
  async decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    if (key.length === 0) throw new EmptyKeyError();
    if (key.length !== AES_GCM_KEY_LENGTH) throw new InvalidKeyError();
    if (iv.length === 0) throw new EmptyIVError();

    const crypto = this.getSubtleCrypto();
    const aesKey = await crypto.importKey('raw', key as BufferSource, 'AES-GCM', false, [
      'decrypt',
    ]);

    const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
    if (aad && aad.length > 0) params.additionalData = aad as BufferSource;

    const decrypted = await crypto.decrypt(params, aesKey, ciphertext as BufferSource).catch(() => {
      throw new DecryptionError();
    });

    return new Uint8Array(decrypted);
  }
}

// Automatically register the provider upon module import.
EncryptionFactory.addProvider(new AESGCMProvider());
