import { EncryptionFactory } from './encryption/encryption';
import { Key } from './key';
import { EncodingFactory } from './encoding/encoding';
import { RandomnessFactory } from './randomness/randomness';
import {
  DisallowedProviderError,
  EmptyDataError,
  KeyDisposedError,
  UnsupportedVersionError,
} from './errors';

/**
 * Default set of encryption algorithms accepted on Document.decode. Callers can
 * widen this list to permit custom providers, but the default refuses anything
 * other than the algorithms shipped by this library.
 */
export const DEFAULT_ALLOWED_DOCUMENT_ALGORITHMS: readonly string[] = ['aes-gcm'];

/**
 * The current version of the serialized Document format.
 *
 * v2 binds the format version and algorithm name into the AES-GCM
 * Additional Authenticated Data so attackers cannot rewrite envelope
 * metadata without invalidating the auth tag. v1 envelopes (which lack
 * AAD) are still accepted for read-back compatibility.
 */
const DOCUMENT_VERSION = 2;

/**
 * Builds the AAD payload bound to a v2 Document. Must be reconstructed
 * deterministically on decrypt; any deviation (version, algorithm) yields
 * an authentication failure.
 */
function buildDocumentAAD(version: number, algorithm: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ v: version, a: algorithm }));
}

/**
 * The standard length for the initialization vector used in Document encryption (96 bits).
 * 12 bytes is optimal for AES-GCM as it fits perfectly into the algorithm's counter initialization.
 */
export const DOCUMENT_IV_LENGTH = 12;

/**
 * Represents metadata about the encryption used in a Document.
 */
export interface DocumentMetadata {
  /** The initialization vector used for encrypting the data. */
  iv: Uint8Array;
  /** The name of the encryption algorithm used (e.g., 'aes-gcm'). */
  algorithm: string;
}

/**
 * Represents an encrypted data container (Document).
 * This class holds the ciphertext and the metadata required to decrypt it using a Key.
 */
export class Document {
  /**
   * The format version this Document was created with. Drives the AAD binding
   * decision on decrypt: v2+ uses AAD, v1 does not.
   */
  public readonly version: number;

  /**
   * @param ciphertext - The encrypted data.
   * @param metadata - Information about the encryption (IV, algorithm).
   * @param version - Format version. Defaults to the current {@link DOCUMENT_VERSION}.
   */
  constructor(
    public readonly ciphertext: Uint8Array,
    public readonly metadata: DocumentMetadata,
    version: number = DOCUMENT_VERSION,
  ) {
    this.version = version;
  }

  /**
   * Encrypts plaintext data using an unlocked Key.
   *
   * @param data - The raw data to encrypt.
   * @param key - An unlocked Key instance containing the 256-bit material.
   * @param options - Configuration for the providers used during encryption.
   * @param options.encryptionProvider - The name of the encryption provider (defaults to 'aes-gcm').
   * @param options.randomnessProvider - The name of the randomness provider for the IV.
   * @returns A promise that resolves to a new Document instance.
   * @throws {EmptyDataError} If the input data is empty.
   */
  static async encrypt(
    data: Uint8Array,
    key: Key,
    options: {
      encryptionProvider?: string;
      randomnessProvider?: string;
    } = {},
  ): Promise<Document> {
    if (data.length === 0) {
      throw new EmptyDataError();
    }
    if (key.disposed) throw new KeyDisposedError();
    const encryption = EncryptionFactory.getProvider(options.encryptionProvider || 'aes-gcm');
    const randomness = RandomnessFactory.getProvider(options.randomnessProvider || 'native');

    const iv = randomness.generate(DOCUMENT_IV_LENGTH);
    const aad = buildDocumentAAD(DOCUMENT_VERSION, encryption.name);
    const ciphertext = await encryption.encrypt(data, key.material, iv, aad);

    return new Document(
      ciphertext,
      {
        iv,
        algorithm: encryption.name,
      },
      DOCUMENT_VERSION,
    );
  }

  /**
   * Decrypts the document's content using an unlocked Key.
   *
   * @param key - An unlocked Key instance corresponding to the one used for encryption.
   * @returns A promise that resolves to the original decrypted data.
   */
  async decrypt(key: Key): Promise<Uint8Array> {
    if (key.disposed) throw new KeyDisposedError();
    const encryption = EncryptionFactory.getProvider(this.metadata.algorithm);
    const aad =
      this.version >= 2 ? buildDocumentAAD(this.version, this.metadata.algorithm) : undefined;
    return await encryption.decrypt(this.ciphertext, key.material, this.metadata.iv, aad);
  }

  /**
   * Serializes the Document to an encoded string (e.g., Base64).
   * @param encodingProvider - The name of the encoding provider to use (defaults to 'base64').
   * @returns The encoded string representation of the Document.
   */
  encode(encodingProvider = 'base64'): string {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data = {
      v: this.version,
      c: encoding.encode(this.ciphertext),
      m: {
        i: encoding.encode(this.metadata.iv),
        a: this.metadata.algorithm,
      },
    };
    return encoding.btoa(JSON.stringify(data));
  }

  /**
   * Deserializes a Document from an encoded string.
   * @param encoded - The encoded string representation of the Document.
   * @param options - Optional decode configuration.
   * @param options.encodingProvider - Encoding provider name. Defaults to 'base64'.
   * @param options.allowedAlgorithms - Encryption algorithm names accepted from
   * the envelope. Defaults to {@link DEFAULT_ALLOWED_DOCUMENT_ALGORITHMS}.
   * Decoding rejects any other value to prevent envelope-driven provider
   * substitution. Pass an explicit list to opt into custom providers.
   * @returns A Document instance.
   * @throws {UnsupportedVersionError} If the version in the encoded data is not supported.
   * @throws {DisallowedProviderError} If the algorithm name is not on the allowlist.
   */
  static decode(
    encoded: string,
    options:
      | string
      | {
          encodingProvider?: string;
          allowedAlgorithms?: readonly string[];
        } = {},
  ): Document {
    const opts = typeof options === 'string' ? { encodingProvider: options } : options;
    const encodingProvider = opts.encodingProvider ?? 'base64';
    const allowed = opts.allowedAlgorithms ?? DEFAULT_ALLOWED_DOCUMENT_ALGORITHMS;

    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data: { v: number; c: string; m: { i: string; a: string } } = JSON.parse(
      encoding.atob(encoded),
    );

    if (data.v !== DOCUMENT_VERSION && data.v !== 1) {
      throw new UnsupportedVersionError(data.v, DOCUMENT_VERSION);
    }
    if (!allowed.includes(data.m.a)) {
      throw new DisallowedProviderError('Encryption', data.m.a, allowed);
    }

    return new Document(
      encoding.decode(data.c),
      {
        iv: encoding.decode(data.m.i),
        algorithm: data.m.a,
      },
      data.v,
    );
  }
}
