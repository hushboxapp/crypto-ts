export * from './encoding/encoding';
export * from './encoding/base64';
export * from './encryption/encryption';
export * from './encryption/aes-gcm';
export * from './hashing/hashing';
export * from './hashing/argon2';
export * from './hashing/argon2-worker-provider';
export * from './randomness/randomness';
export * from './randomness/native';
export * from './sharing/sharing';
export * from './sharing/shamir';
export * from './key';
export * from './document';
export * from './factory';
export * from './errors';

// High-level helpers for backward compatibility
import { RandomnessFactory } from './randomness/randomness';
import { SharingFactory } from './sharing/sharing';
import { EncryptionFactory } from './encryption/encryption';

export function generateRandomBytes(length: number): Uint8Array {
  return RandomnessFactory.getProvider('native').generate(length);
}

export async function splitKey(secret: Uint8Array, n: number, t: number): Promise<Uint8Array[]> {
  return await SharingFactory.getProvider('shamir').split(secret, n, t);
}

export async function combineShares(shares: Uint8Array[]): Promise<Uint8Array> {
  return await SharingFactory.getProvider('shamir').combine(shares);
}

export async function encryptWithDEK(
  data: Uint8Array,
  kek: Uint8Array
): Promise<{
  ciphertext: Uint8Array;
  wrappedDEK: Uint8Array;
  dataIV: Uint8Array;
  dekIV: Uint8Array;
}> {
  const encryption = EncryptionFactory.getProvider('aes-gcm');
  const randomness = RandomnessFactory.getProvider('native');

  const dek = randomness.generate(32);
  const dataIV = randomness.generate(12);
  const dekIV = randomness.generate(12);

  const ciphertext = await encryption.encrypt(data, dek, dataIV);
  const wrappedDEK = await encryption.encrypt(dek, kek, dekIV);

  return {
    ciphertext,
    wrappedDEK,
    dataIV,
    dekIV,
  };
}

export async function decryptWithDEK(
  ciphertext: Uint8Array,
  wrappedDEK: Uint8Array,
  kek: Uint8Array,
  dataIV: Uint8Array,
  dekIV: Uint8Array
): Promise<Uint8Array> {
  const encryption = EncryptionFactory.getProvider('aes-gcm');

  const dek = await encryption.decrypt(wrappedDEK, kek, dekIV);
  return await encryption.decrypt(ciphertext, dek, dataIV);
}
