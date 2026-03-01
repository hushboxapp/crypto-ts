import { argon2id } from 'hash-wasm';
import { HashingProvider, HashingFactory } from './hashing';

export interface Argon2Options {
  salt: Uint8Array;
  parallelism?: number;
  iterations?: number;
  memorySize?: number; // in KiB
  hashLength?: number; // in bytes
}

const DEFAULT_ARGON2_OPTIONS = {
  parallelism: 1,
  iterations: 2,
  memorySize: 65536, // 64 MB
  hashLength: 32, // 256 bits
};

/**
 * Derives a key from a password using Argon2id.
 * @param password The user password.
 * @param options Argon2id parameters and salt.
 * @returns The derived key as a Uint8Array.
 */
export async function deriveKey(password: string, options: Argon2Options): Promise<Uint8Array> {
  const params = {
    ...DEFAULT_ARGON2_OPTIONS,
    ...options,
  };

  const hash = await argon2id({
    password,
    salt: params.salt,
    parallelism: params.parallelism,
    iterations: params.iterations,
    memorySize: params.memorySize,
    hashLength: params.hashLength,
    outputType: 'binary',
  });

  return hash;
}

/**
 * Argon2id implementation of HashingProvider.
 */
export class Argon2Provider implements HashingProvider {
  readonly name = 'argon2id';
  constructor(private options: Partial<Argon2Options> = {}) {}

  async derive(password: string, salt: Uint8Array): Promise<Uint8Array> {
    return await deriveKey(password, { ...this.options, salt });
  }

  getParams(): Record<string, unknown> {
    return { ...DEFAULT_ARGON2_OPTIONS, ...this.options };
  }
}

HashingFactory.addProvider(new Argon2Provider());
