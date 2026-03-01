import { RandomnessProvider, RandomnessFactory } from './randomness';
import { SecureContextError } from '../errors';

export class NativeProvider implements RandomnessProvider {
  readonly name = 'native';
  generate(length: number): Uint8Array {
    if (typeof globalThis !== 'undefined' && 'isSecureContext' in globalThis && !globalThis.isSecureContext) {
      throw new SecureContextError();
    }

    const bytes = new Uint8Array(length);
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(bytes);
    } else {
      // @ts-ignore
      globalThis.crypto.getRandomValues(bytes);
    }
    return bytes;
  }
}

RandomnessFactory.addProvider(new NativeProvider());
