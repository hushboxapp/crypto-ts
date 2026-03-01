import { Factory, NamedProvider } from '../factory';

export interface EncryptionProvider extends NamedProvider {
  encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
}

export const EncryptionFactory = new Factory<EncryptionProvider>('Encryption');
