import { SharingProvider, SharingFactory } from './sharing';
import { RandomnessFactory } from '../randomness/randomness';
import '../randomness/native';
import { InvalidThresholdError, InvalidShareCountError, EmptyDataError } from '../errors';
import { splitSecret, combineShares } from './shamir-core';

/**
 * An implementation of SharingProvider using Shamir's Secret Sharing scheme.
 * It uses polynomial interpolation over GF(2^8) to allow secret reconstruction
 * from a subset of shares. The core math lives in {@link ./shamir-core}; this
 * class adds typed argument validation and routes randomness through the
 * caller-configured {@link RandomnessFactory}.
 */
export class ShamirProvider implements SharingProvider {
  /** The unique identifier for this provider. */
  readonly name = 'shamir';

  /**
   * @param randomnessProvider - Name of the randomness provider used to draw
   * polynomial coefficients and x-coordinate orderings. Defaults to 'native'.
   */
  constructor(private readonly randomnessProvider: string = 'native') {}

  /**
   * Splits a secret into N shares with a threshold of T.
   *
   * @param secret - The secret material to split.
   * @param n - Total shares to generate.
   * @param t - Minimum shares required for reconstruction.
   * @returns A promise resolving to the generated shares.
   * @throws {EmptyDataError} If the secret is empty.
   * @throws {InvalidShareCountError} If N is less than 2 or greater than 255.
   * @throws {InvalidThresholdError} If T is less than 2 or greater than N.
   */
  async split(secret: Uint8Array, n: number, t: number): Promise<Uint8Array[]> {
    if (secret.length === 0) {
      throw new EmptyDataError('Secret material cannot be empty.');
    }
    if (!Number.isInteger(n) || n < 2 || n > 255) {
      throw new InvalidShareCountError();
    }
    if (!Number.isInteger(t) || t < 2 || t > n) {
      throw new InvalidThresholdError(
        'Invalid threshold: must be an integer between 2 and the number of shares.',
      );
    }
    const randomness = RandomnessFactory.getProvider(this.randomnessProvider);
    return splitSecret(secret, n, t, (count) => randomness.generate(count));
  }

  /**
   * Reconstructs the secret from the provided shares.
   * @param shares - An array of shares.
   * @returns A promise resolving to the combined secret.
   */
  async combine(shares: Uint8Array[]): Promise<Uint8Array> {
    return combineShares(shares);
  }
}

// Automatically register the provider upon module import.
SharingFactory.addProvider(new ShamirProvider());
