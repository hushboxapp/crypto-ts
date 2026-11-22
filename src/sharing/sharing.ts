import { Factory, NamedProvider } from '../factory';

/**
 * Interface for secret sharing engines (M-of-N).
 * Providers must implement a scheme to split a secret into multiple shares
 * and reconstruct it from a subset of those shares.
 */
export interface SharingProvider extends NamedProvider {
  /**
   * Splits a secret buffer into N shares, with a threshold of T.
   *
   * @param secret - The raw material to split.
   * @param n - The total number of shares to generate.
   * @param t - The threshold (minimum number of shares needed to reconstruct).
   * @returns A promise that resolves to an array of N share buffers.
   */
  split(secret: Uint8Array, n: number, t: number): Promise<Uint8Array[]>;

  /**
   * Reconstructs the original secret from a set of shares.
   *
   * @param shares - An array of at least T shares.
   * @returns A promise that resolves to the original secret material.
   */
  combine(shares: Uint8Array[]): Promise<Uint8Array>;
}

/**
 * Global factory for managing secret sharing providers.
 */
export const SharingFactory: Factory<SharingProvider> = new Factory<SharingProvider>('Sharing');
