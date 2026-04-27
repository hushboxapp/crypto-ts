import {
  InvalidKeyError,
  InvalidThresholdError,
  InsufficientSharesError,
  EmptyPasswordsError,
  EmptyKeyError,
  UnsupportedVersionError,
} from './errors';
import { SharingFactory } from './sharing/sharing';
import { EncryptionFactory } from './encryption/encryption';
import { HashingFactory } from './hashing/hashing';
import { EncodingFactory } from './encoding/encoding';
import { RandomnessFactory } from './randomness/randomness';

/**
 * The standard length for the master key material (256 bits).
 */
export const KEY_MATERIAL_LENGTH = 32;

/**
 * The standard length for the salt used to protect key shares (128 bits).
 */
export const KEY_PROTECTOR_SALT_LENGTH = 16;

/**
 * The standard length for the IV used to protect key shares (96 bits).
 * 12 bytes is the recommended size for AES-GCM to avoid additional hashing of the IV.
 */
export const KEY_PROTECTOR_IV_LENGTH = 12;

/**
 * The current version of the serialized Key format.
 */
const KEY_VERSION = 2;

/**
 * Argon2id parameters used by version 1 of the Key format. Hard-coded so that
 * v1 keys can still be decrypted after the library defaults are tuned.
 */
const LEGACY_V1_HASHING_PARAMS: Record<string, unknown> = {
  parallelism: 1,
  iterations: 2,
  memorySize: 65536,
  hashLength: 32,
};

/**
 * Represents metadata about how a specific share of a Key is protected.
 */
export interface KeyProtector {
  /** The unique salt used for key derivation for this specific protector. */
  salt: Uint8Array;
  /** The initialization vector used for encrypting this share. */
  iv: Uint8Array;
  /** The encrypted key material share. */
  ciphertext: Uint8Array;
  /** The name of the hashing algorithm used to derive the encryption key from a password. */
  hashingAlgorithm: string;
  /**
   * The exact algorithm parameters that were active when this share was protected.
   * Persisted so that decryption keeps working even if the library defaults change later.
   */
  hashingParams: Record<string, unknown>;
}

/**
 * Represents an unlocked cryptographic Key in memory.
 * This class holds the raw sensitive material and provides methods to protect it for persistence.
 */
export class Key {
  /**
   * Creates a new Key instance from raw material.
   * @param material - The 256-bit (32 bytes) raw key material.
   * @throws {EmptyKeyError} If the material is empty.
   * @throws {InvalidKeyError} If the material is not exactly 32 bytes.
   */
  constructor(public readonly material: Uint8Array) {
    if (material.length === 0) {
      throw new EmptyKeyError();
    }
    if (material.length !== KEY_MATERIAL_LENGTH) {
      throw new InvalidKeyError();
    }
  }

  /**
   * Generates a new random 256-bit Key using the specified randomness provider.
   * @param randomnessProvider - The name of the randomness provider to use (defaults to 'native').
   * @returns A new Key instance with random material.
   */
  static generate(randomnessProvider = 'native'): Key {
    const randomness = RandomnessFactory.getProvider(randomnessProvider);
    return new Key(randomness.generate(KEY_MATERIAL_LENGTH));
  }

  /**
   * Encrypts (locks) this key with one or more passwords using an M-of-N scheme.
   * The key is split into N shares, and each share is encrypted with a key derived from a password.
   *
   * @param passwords - An array of N passwords to protect the key shares.
   * @param threshold - The minimum number of passwords (M) required to reconstruct the key later.
   * @param options - Configuration for the providers used during encryption.
   * @param options.hashingProvider - The name of the hashing provider for password derivation (e.g., 'argon2id').
   * @param options.sharingProvider - The name of the sharing provider for M-of-N splitting (e.g., 'shamir').
   * @param options.encryptionProvider - The name of the encryption provider for protecting shares (e.g., 'aes-gcm').
   * @param options.randomnessProvider - The name of the randomness provider for salts and IVs.
   * @returns A promise that resolves to an EncryptedKey instance.
   * @throws {EmptyPasswordsError} If the passwords array is empty.
   * @throws {InvalidThresholdError} If the threshold is less than 1 or greater than the number of passwords.
   */
  async encrypt(
    passwords: string[],
    threshold: number,
    options: {
      hashingProvider?: string;
      sharingProvider?: string;
      encryptionProvider?: string;
      randomnessProvider?: string;
    } = {},
  ): Promise<EncryptedKey> {
    if (passwords.length === 0) {
      throw new EmptyPasswordsError();
    }
    const n = passwords.length;
    if (threshold > n || threshold < 1) throw new InvalidThresholdError();

    const sharing = SharingFactory.getProvider(options.sharingProvider || 'shamir');
    const encryption = EncryptionFactory.getProvider(options.encryptionProvider || 'aes-gcm');
    const randomness = RandomnessFactory.getProvider(options.randomnessProvider || 'native');
    const hashing = HashingFactory.getProvider(options.hashingProvider || 'argon2id');

    let shares: Uint8Array[];
    if (n === 1 || threshold === 1) {
      // Threshold of 1: every protector holds a copy of the material. No
      // secret sharing needed — any single password reconstructs the key.
      shares = Array.from({ length: n }, () => new Uint8Array(this.material));
    } else {
      shares = await sharing.split(this.material, n, threshold);
    }

    const protectors: KeyProtector[] = [];

    const hashingParams = hashing.getParams();
    for (let i = 0; i < n; i++) {
      const salt = randomness.generate(KEY_PROTECTOR_SALT_LENGTH);
      const iv = randomness.generate(KEY_PROTECTOR_IV_LENGTH);
      const passwordKey = await hashing.derive(passwords[i], salt, hashingParams);
      const ciphertext = await encryption.encrypt(shares[i], passwordKey, iv);

      protectors.push({
        salt,
        iv,
        ciphertext,
        hashingAlgorithm: hashing.name,
        hashingParams: { ...hashingParams },
      });
    }

    return new EncryptedKey(protectors, threshold, encryption.name, sharing.name);
  }
}

/**
 * Represents a locked/encrypted Key, suitable for persistence or transmission.
 * It contains the encrypted shares and metadata required to reconstruct the original Key.
 */
export class EncryptedKey {
  /**
   * @param protectors - Metadata and encrypted material for each key share.
   * @param threshold - The number of shares required to reconstruct the key.
   * @param encryptionProvider - The name of the provider used to encrypt the shares.
   * @param sharingProvider - The name of the provider used to split the key material.
   */
  constructor(
    public readonly protectors: KeyProtector[],
    public readonly threshold: number,
    public readonly encryptionProvider: string,
    public readonly sharingProvider: string,
  ) {}

  /**
   * Decrypts (unlocks) the Key using the provided passwords.
   * It attempts to unlock each share protector with the given passwords until the threshold is met.
   *
   * @param passwords - An array of passwords. At least `threshold` correct passwords must be present.
   * @returns A promise that resolves to the reconstructed Key instance.
   * @throws {EmptyPasswordsError} If no passwords are provided.
   * @throws {InsufficientSharesError} If the number of successfully unlocked shares is below the threshold.
   */
  async decrypt(passwords: string[]): Promise<Key> {
    if (passwords.length === 0) {
      throw new EmptyPasswordsError();
    }
    const shares: Uint8Array[] = [];
    const encryption = EncryptionFactory.getProvider(this.encryptionProvider);
    const sharing = SharingFactory.getProvider(this.sharingProvider);

    // Attempt to unlock protectors using the provided passwords
    for (const password of passwords) {
      for (const protector of this.protectors) {
        try {
          const hashing = HashingFactory.getProvider(protector.hashingAlgorithm);
          const passwordKey = await hashing.derive(
            password,
            protector.salt,
            protector.hashingParams,
          );
          const share = await encryption.decrypt(protector.ciphertext, passwordKey, protector.iv);
          shares.push(share);
          break; // This password unlocked a share
        } catch {
          continue; // Try next protector
        }
      }
      if (shares.length >= this.threshold) break;
    }

    if (shares.length < this.threshold) {
      throw new InsufficientSharesError(shares.length, this.threshold);
    }

    const material = this.threshold === 1 ? shares[0] : await sharing.combine(shares);
    return new Key(material);
  }

  /**
   * Serializes the encrypted key to an encoded string (e.g., Base64).
   * @param encodingProvider - The name of the encoding provider to use (defaults to 'base64').
   * @returns The encoded string representation of the encrypted key.
   */
  encode(encodingProvider = 'base64'): string {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data = {
      v: KEY_VERSION,
      t: this.threshold,
      e: this.encryptionProvider,
      s: this.sharingProvider,
      p: this.protectors.map((p) => ({
        s: encoding.encode(p.salt),
        i: encoding.encode(p.iv),
        c: encoding.encode(p.ciphertext),
        a: p.hashingAlgorithm,
        h: p.hashingParams,
      })),
    };
    return encoding.btoa(JSON.stringify(data));
  }

  /**
   * Deserializes an encrypted key from an encoded string.
   * @param encoded - The encoded string representation of the encrypted key.
   * @param encodingProvider - The name of the encoding provider to use (defaults to 'base64').
   * @returns An EncryptedKey instance.
   * @throws {UnsupportedVersionError} If the version in the encoded data is not supported.
   */
  static decode(encoded: string, encodingProvider = 'base64'): EncryptedKey {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data = JSON.parse(encoding.atob(encoded));

    if (data.v !== KEY_VERSION && data.v !== 1) {
      throw new UnsupportedVersionError(data.v, KEY_VERSION);
    }

    const protectors: KeyProtector[] = data.p.map(
      (p: { s: string; i: string; c: string; a: string; h?: Record<string, unknown> }) => ({
        salt: encoding.decode(p.s),
        iv: encoding.decode(p.i),
        ciphertext: encoding.decode(p.c),
        hashingAlgorithm: p.a,
        hashingParams: p.h ?? { ...LEGACY_V1_HASHING_PARAMS },
      }),
    );
    return new EncryptedKey(protectors, data.t, data.e, data.s);
  }
}
