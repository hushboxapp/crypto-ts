import { Factory, NamedProvider } from '../factory';

export interface HashingProvider extends NamedProvider {
  derive(password: string, salt: Uint8Array): Promise<Uint8Array>;
  getParams(): Record<string, unknown>;
}

export const HashingFactory = new Factory<HashingProvider>('Hashing');
