import { EncryptionProvider, EncryptionFactory } from './encryption';
import { SecureContextError, DecryptionError, CryptoApiUnavailableError, EmptyDataError, EmptyKeyError, EmptyIVError } from '../errors';

export class AESGCMProvider implements EncryptionProvider {
  readonly name = 'aes-gcm';
  private getSubtleCrypto(): SubtleCrypto {
    if (typeof globalThis !== 'undefined' && 'isSecureContext' in globalThis && !globalThis.isSecureContext) {
      throw new SecureContextError();
    }

    if (typeof window !== 'undefined' && window.crypto) {
      return window.crypto.subtle;
    }
    // @ts-ignore
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
      // @ts-ignore
      return globalThis.crypto.subtle;
    }
    throw new CryptoApiUnavailableError();
  }

  async encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    if (data.length === 0) throw new EmptyDataError();
    if (key.length === 0) throw new EmptyKeyError();
    if (iv.length === 0) throw new EmptyIVError();

    const crypto = this.getSubtleCrypto();
    const aesKey = await crypto.importKey(
      'raw',
      key as BufferSource,
      'AES-GCM',
      false,
      ['encrypt']
    );

    const encrypted = await crypto.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      aesKey,
      data as BufferSource
    );

    return new Uint8Array(encrypted);
  }

  async decrypt(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    if (ciphertext.length === 0) throw new EmptyDataError('Ciphertext cannot be empty.');
    if (key.length === 0) throw new EmptyKeyError();
    if (iv.length === 0) throw new EmptyIVError();

    const crypto = this.getSubtleCrypto();
    const aesKey = await crypto.importKey(
      'raw',
      key as BufferSource,
      'AES-GCM',
      false,
      ['decrypt']
    );

    const decrypted = await crypto.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      aesKey,
      ciphertext as BufferSource
    ).catch(() => {
      throw new DecryptionError();
    });

    return new Uint8Array(decrypted);
  }
}

EncryptionFactory.addProvider(new AESGCMProvider());
