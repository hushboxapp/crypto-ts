import { RandomnessProvider, RandomnessFactory } from './randomness';
import { CryptoApiUnavailableError, SecureContextError } from '../errors';

/**
 * An implementation of RandomnessProvider using the environment's native CSPRNG.
 * In browsers, this uses `crypto.getRandomValues()`. In Node.js, it uses the `crypto` module.
 */
export class NativeProvider implements RandomnessProvider {
  /** The unique identifier for this provider. */
  readonly name = 'native';

  /**
   * Generates cryptographically secure random bytes.
   *
   * @param length - The number of bytes to generate.
   * @returns A Uint8Array of random bytes.
   * @throws {SecureContextError} If the environment is an insecure browser context.
   * @throws {CryptoApiUnavailableError} If crypto.getRandomValues is not available.
   */
  generate(length: number): Uint8Array {
    if (
      typeof globalThis !== 'undefined' &&
      'isSecureContext' in globalThis &&
      !globalThis.isSecureContext
    ) {
      throw new SecureContextError();
    }

    const bytes = new Uint8Array(length);
    const crypto = globalThis.crypto;
    if (!crypto || typeof crypto.getRandomValues !== 'function') {
      throw new CryptoApiUnavailableError();
    }
    crypto.getRandomValues(bytes);
    return bytes;
  }
}

// Automatically register the provider upon module import.
RandomnessFactory.addProvider(new NativeProvider());
