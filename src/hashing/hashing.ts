import { Factory, NamedProvider } from '../factory';

/**
 * Interface for key derivation functions (hashing).
 * Hashing providers are responsible for deriving high-entropy keys from lower-entropy passwords.
 */
export interface HashingProvider extends NamedProvider {
  /**
   * Derives a cryptographic key from a password and salt.
   *
   * @param password - The user-provided password string or raw bytes.
   * @param salt - A cryptographically random buffer to prevent rainbow table attacks.
   * @param params - Optional algorithm parameters. When provided, overrides the provider's
   * configured defaults for this single call. Used during decryption to re-derive with the
   * exact parameters that were active when the key was originally protected.
   * @returns A promise that resolves to the derived 256-bit key material.
   */
  derive(
    password: string | Uint8Array,
    salt: Uint8Array,
    params?: Record<string, unknown>,
  ): Promise<Uint8Array>;

  /**
   * Retrieves the specific parameters used by this hashing instance.
   * Useful for auditing or recreating the environment.
   * @returns An object containing the algorithm's configuration.
   */
  getParams(): Record<string, unknown>;
}

/**
 * Global factory for managing hashing (KDF) providers.
 */
export const HashingFactory = new Factory<HashingProvider>('Hashing');
