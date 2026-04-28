import { EncodingProvider, EncodingFactory } from './encoding';
import { InvalidEncodingError } from '../errors';

/**
 * Chunk size used when converting Uint8Array to a binary string before
 * encoding. {@link String.fromCharCode} accepts a variadic argument list and
 * blows the stack on very large inputs; processing the buffer in fixed-size
 * chunks keeps encode at O(n) time and constant stack depth.
 */
const ENCODE_CHUNK_SIZE = 0x8000;

/**
 * An implementation of EncodingProvider using the Base64 scheme.
 *
 * Uses the platform-native {@link globalThis.atob} / {@link globalThis.btoa}
 * (available in browsers and Node 16+) so no environment branching is needed.
 * Binary encode/decode use a chunked latin-1 bridge to avoid the O(n^2)
 * blow-up of `Array.from(data).map(...).join('')` on large payloads.
 */
export class Base64Engine implements EncodingProvider {
  /** The unique identifier for this provider. */
  readonly name = 'base64';

  /**
   * Encodes a string into its Base64 representation.
   * @param str - The raw string.
   * @returns The Base64 encoded string.
   */
  btoa(str: string): string {
    return globalThis.btoa(str);
  }

  /**
   * Decodes a Base64 encoded string.
   * @param b64 - The Base64 string.
   * @returns The decoded original string.
   * @throws {InvalidEncodingError} If the input is not a valid Base64 string.
   */
  atob(b64: string): string {
    try {
      return globalThis.atob(b64);
    } catch (err) {
      // Native atob throws DOMException ('InvalidCharacterError'). Wrap it so
      // callers only ever see library-domain errors.
      throw new InvalidEncodingError('base64', err);
    }
  }

  /**
   * Encodes binary data (Uint8Array) into its Base64 representation.
   * @param data - The raw bytes to encode.
   * @returns The Base64 encoded string.
   */
  encode(data: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < data.length; i += ENCODE_CHUNK_SIZE) {
      const chunk = data.subarray(i, i + ENCODE_CHUNK_SIZE);
      binary += String.fromCharCode.apply(null, chunk as unknown as number[]);
    }
    return globalThis.btoa(binary);
  }

  /**
   * Decodes a Base64 encoded string into binary data (Uint8Array).
   * @param b64 - The Base64 string.
   * @returns The decoded bytes as a Uint8Array.
   * @throws {InvalidEncodingError} If the input is not a valid Base64 string.
   */
  decode(b64: string): Uint8Array {
    const binary = this.atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

// Automatically register the provider upon module import.
EncodingFactory.addProvider(new Base64Engine());
