import { EncryptionFactory } from './encryption/encryption';
import { Key } from './key';
import { EncodingFactory } from './encoding/encoding';
import { RandomnessFactory } from './randomness/randomness';
import { EmptyDataError, UnsupportedVersionError } from './errors';

/**
 * The current version of the serialized Document format.
 */
const DOCUMENT_VERSION = 1;

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
   * @param ciphertext - The encrypted data.
   * @param metadata - Information about the encryption (IV, algorithm).
   */
  constructor(
    public readonly ciphertext: Uint8Array,
    public readonly metadata: DocumentMetadata,
  ) {}

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
    const encryption = EncryptionFactory.getProvider(options.encryptionProvider || 'aes-gcm');
    const randomness = RandomnessFactory.getProvider(options.randomnessProvider || 'native');

    const iv = randomness.generate(DOCUMENT_IV_LENGTH);
    const ciphertext = await encryption.encrypt(data, key.material, iv);

    return new Document(ciphertext, {
      iv,
      algorithm: encryption.name,
    });
  }

  /**
   * Decrypts the document's content using an unlocked Key.
   *
   * @param key - An unlocked Key instance corresponding to the one used for encryption.
   * @returns A promise that resolves to the original decrypted data.
   */
  async decrypt(key: Key): Promise<Uint8Array> {
    const encryption = EncryptionFactory.getProvider(this.metadata.algorithm);
    return await encryption.decrypt(this.ciphertext, key.material, this.metadata.iv);
  }

  /**
   * Serializes the Document to an encoded string (e.g., Base64).
   * @param encodingProvider - The name of the encoding provider to use (defaults to 'base64').
   * @returns The encoded string representation of the Document.
   */
  encode(encodingProvider = 'base64'): string {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data = {
      v: DOCUMENT_VERSION,
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
   * @param encodingProvider - The name of the encoding provider to use (defaults to 'base64').
   * @returns A Document instance.
   * @throws {UnsupportedVersionError} If the version in the encoded data is not supported.
   */
  static decode(encoded: string, encodingProvider = 'base64'): Document {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data: { v: number; c: string; m: { i: string; a: string } } = JSON.parse(
      encoding.atob(encoded),
    );

    if (data.v !== DOCUMENT_VERSION) {
      throw new UnsupportedVersionError(data.v, DOCUMENT_VERSION);
    }

    return new Document(encoding.decode(data.c), {
      iv: encoding.decode(data.m.i),
      algorithm: data.m.a,
    });
  }
}
