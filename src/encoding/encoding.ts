import { Factory, NamedProvider } from '../factory';

/**
 * Interface for encoding engines.
 * Providers are responsible for transforming binary data to string representations and vice versa.
 */
export interface EncodingProvider extends NamedProvider {
  /**
   * Encodes a string into its encoded representation.
   * @param str - The string to encode.
   * @returns The encoded string.
   */
  btoa(str: string): string;

  /**
   * Decodes an encoded string back to its original representation.
   * @param encoded - The encoded string.
   * @returns The decoded string.
   */
  atob(encoded: string): string;

  /**
   * Encodes binary data (Uint8Array) into a string representation.
   * @param data - The raw bytes to encode.
   * @returns The encoded string.
   */
  encode(data: Uint8Array): string;

  /**
   * Decodes an encoded string back to its original binary representation.
   * @param encoded - The encoded string.
   * @returns The decoded bytes as a Uint8Array.
   */
  decode(encoded: string): Uint8Array;
}

/**
 * Global factory for managing encoding providers.
 */
export const EncodingFactory = new Factory<EncodingProvider>('Encoding');
