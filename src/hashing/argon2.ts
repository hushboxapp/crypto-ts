import { argon2id } from 'hash-wasm';
import { HashingProvider, HashingFactory } from './hashing';

/**
 * Options for configuring the Argon2id key derivation algorithm.
 * Argon2id is highly resistant to GPU-based side-channel and cracking attacks.
 */
export interface Argon2Options {
  /** A unique random buffer used to prevent pre-computation attacks. */
  salt: Uint8Array;
  /** Number of execution threads. Higher values increase cost for attackers. */
  parallelism?: number;
  /** Number of passes over the memory. Higher values increase time cost. */
  iterations?: number;
  /** Amount of memory to use (in KiB). Higher values increase memory cost. */
  memorySize?: number;
  /** The length of the resulting hash (in bytes). 32 is the standard for 256-bit keys. */
  hashLength?: number;
}

/**
 * The default recommended parameters for Argon2id.
 */
export const DEFAULT_ARGON2_OPTIONS = {
  parallelism: 1,
  iterations: 2,
  memorySize: 65536, // 64 MB
  hashLength: 32, // 256 bits
};

/**
 * Low-level helper to derive a key using the Argon2id WebAssembly implementation.
 *
 * @param password - The user password (string or raw bytes).
 * @param options - Argon2id parameters and salt.
 * @returns A promise that resolves to the derived key as a Uint8Array.
 */
export async function deriveKey(
  password: string | Uint8Array,
  options: Argon2Options,
): Promise<Uint8Array> {
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
 * An implementation of HashingProvider using the Argon2id algorithm.
 * This implementation runs on the main thread.
 */
export class Argon2Provider implements HashingProvider {
  /** The unique identifier for this provider. */
  readonly name = 'argon2id';

  /**
   * @param options - Optional custom parameters for Argon2id.
   */
  constructor(private options: Partial<Argon2Options> = {}) {}

  /**
   * Derives a 256-bit key from a password.
   * @param password - The user-provided password (string or raw bytes).
   * @param salt - The cryptographic salt.
   * @returns A promise resolving to the derived key.
   */
  async derive(password: string | Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
    return await deriveKey(password, { ...this.options, salt });
  }

  /**
   * Returns the current Argon2id configuration.
   */
  getParams(): Record<string, unknown> {
    return { ...DEFAULT_ARGON2_OPTIONS, ...this.options };
  }
}

// Automatically register the provider upon module import.
HashingFactory.addProvider(new Argon2Provider());
