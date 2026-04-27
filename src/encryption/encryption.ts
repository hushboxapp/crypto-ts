import { Factory, NamedProvider } from '../factory';

/**
 * Interface for encryption engines.
 * Providers must implement secure symmetric encryption and decryption.
 */
export interface EncryptionProvider extends NamedProvider {
  /**
   * Encrypts the provided data using a symmetric key and initialization vector.
   *
   * @param data - The raw data to encrypt.
   * @param key - The symmetric key material (e.g., 32 bytes for AES-256).
   * @param iv - The initialization vector (e.g., 12 bytes for AES-GCM).
   * @param aad - Optional Additional Authenticated Data. Bound into the auth tag
   * but not encrypted; any tampering on decrypt yields a tag mismatch. Used to
   * authenticate metadata that travels alongside the ciphertext (e.g. format
   * version, algorithm name) so attackers cannot rewrite the envelope.
   * @returns A promise that resolves to the encrypted ciphertext.
   */
  encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>;

  /**
   * Decrypts the provided ciphertext using a symmetric key and initialization vector.
   *
   * @param ciphertext - The encrypted data to decrypt.
   * @param key - The symmetric key material used for encryption.
   * @param iv - The initialization vector used for encryption.
   * @param aad - Optional Additional Authenticated Data. Must exactly match the
   * value passed at encryption time, otherwise decryption fails.
   * @returns A promise that resolves to the original plaintext data.
   */
  decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>;
}

/**
 * Global factory for managing encryption providers.
 */
export const EncryptionFactory = new Factory<EncryptionProvider>('Encryption');
