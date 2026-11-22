import { Factory, NamedProvider } from '../factory';

/**
 * Interface for cryptographically secure random number generators.
 */
export interface RandomnessProvider extends NamedProvider {
  /**
   * Generates a buffer of cryptographically secure random bytes.
   *
   * @param length - The number of bytes to generate.
   * @returns A Uint8Array containing the random bytes.
   */
  generate(length: number): Uint8Array;
}

/**
 * Global factory for managing randomness providers.
 */
export const RandomnessFactory: Factory<RandomnessProvider> = new Factory<RandomnessProvider>(
  'Randomness',
);
