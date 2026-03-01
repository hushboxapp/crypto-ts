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

export const KEY_MATERIAL_LENGTH = 32;
export const KEY_PROTECTOR_SALT_LENGTH = 16;
export const KEY_PROTECTOR_IV_LENGTH = 12;

const KEY_VERSION = 1;

export interface KeyProtector {
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  hashingAlgorithm: string;
}

export class Key {
  constructor(public readonly material: Uint8Array) {
    if (material.length === 0) {
      throw new EmptyKeyError();
    }
    if (material.length !== KEY_MATERIAL_LENGTH) {
      throw new InvalidKeyError();
    }
  }

  static generate(randomnessProvider = 'native'): Key {
    const randomness = RandomnessFactory.getProvider(randomnessProvider);
    return new Key(randomness.generate(KEY_MATERIAL_LENGTH));
  }

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
    if (n === 1) {
      shares = [this.material];
    } else {
      shares = await sharing.split(this.material, n, threshold);
    }

    const protectors: KeyProtector[] = [];

    for (let i = 0; i < n; i++) {
      const salt = randomness.generate(KEY_PROTECTOR_SALT_LENGTH);
      const iv = randomness.generate(KEY_PROTECTOR_IV_LENGTH);
      const passwordKey = await hashing.derive(passwords[i], salt);
      const ciphertext = await encryption.encrypt(shares[i], passwordKey, iv);

      protectors.push({
        salt,
        iv,
        ciphertext,
        hashingAlgorithm: hashing.name,
      });
    }

    return new EncryptedKey(protectors, threshold, encryption.name, sharing.name);
  }
}

export class EncryptedKey {
  constructor(
    public readonly protectors: KeyProtector[],
    public readonly threshold: number,
    public readonly encryptionProvider: string,
    public readonly sharingProvider: string,
  ) {}

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
          const passwordKey = await hashing.derive(password, protector.salt);
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

  encode(encodingProvider = 'base64'): string {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data = {
      v: KEY_VERSION,
      t: this.threshold,
      e: this.encryptionProvider,
      s: this.sharingProvider,
      p: this.protectors.map((p) => ({
        s: Buffer.from(p.salt).toString('base64'),
        i: Buffer.from(p.iv).toString('base64'),
        c: Buffer.from(p.ciphertext).toString('base64'),
        a: p.hashingAlgorithm,
      })),
    };
    return encoding.btoa(JSON.stringify(data));
  }

  static decode(base64: string, encodingProvider = 'base64'): EncryptedKey {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data = JSON.parse(encoding.atob(base64));

    if (data.v !== KEY_VERSION) {
      throw new UnsupportedVersionError(data.v, KEY_VERSION);
    }

    const protectors: KeyProtector[] = data.p.map(
      (p: { s: string; i: string; c: string; a: string }) => ({
        salt: new Uint8Array(Uint8Array.from(Buffer.from(p.s, 'base64'))),
        iv: new Uint8Array(Uint8Array.from(Buffer.from(p.i, 'base64'))),
        ciphertext: new Uint8Array(Uint8Array.from(Buffer.from(p.c, 'base64'))),
        hashingAlgorithm: p.a,
      }),
    );

    return new EncryptedKey(protectors, data.t, data.e, data.s);
  }
}
