import { EncryptionFactory } from './encryption/encryption';
import { Key } from './key';
import { EncodingFactory } from './encoding/encoding';
import { RandomnessFactory } from './randomness/randomness';
import { EmptyDataError } from './errors';

export interface DocumentMetadata {
  iv: Uint8Array;
  algorithm: string;
}

export class Document {
  constructor(
    public readonly ciphertext: Uint8Array,
    public readonly metadata: DocumentMetadata
  ) {}

  static async encrypt(
    data: Uint8Array, 
    key: Key, 
    options: {
      encryptionProvider?: string;
      randomnessProvider?: string;
    } = {}
  ): Promise<Document> {
    if (data.length === 0) {
      throw new EmptyDataError();
    }
    const encryption = EncryptionFactory.getProvider(options.encryptionProvider || 'aes-gcm');
    const randomness = RandomnessFactory.getProvider(options.randomnessProvider || 'native');
    
    const iv = randomness.generate(12);
    const ciphertext = await encryption.encrypt(data, key.material, iv);
    
    return new Document(ciphertext, {
      iv,
      algorithm: encryption.name
    });
  }

  async decrypt(
    key: Key
  ): Promise<Uint8Array> {
    const encryption = EncryptionFactory.getProvider(this.metadata.algorithm);
    return await encryption.decrypt(this.ciphertext, key.material, this.metadata.iv);
  }

  encode(encodingProvider = 'base64'): string {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data = {
      c: Buffer.from(this.ciphertext).toString('base64'),
      m: {
        i: Buffer.from(this.metadata.iv).toString('base64'),
        a: this.metadata.algorithm
      }
    };
    return encoding.btoa(JSON.stringify(data));
  }

  static decode(base64: string, encodingProvider = 'base64'): Document {
    const encoding = EncodingFactory.getProvider(encodingProvider);
    const data = JSON.parse(encoding.atob(base64));
    return new Document(
      new Uint8Array(Uint8Array.from(Buffer.from(data.c, 'base64'))),
      {
        iv: new Uint8Array(Uint8Array.from(Buffer.from(data.m.i, 'base64'))),
        algorithm: data.m.a
      }
    );
  }
}
