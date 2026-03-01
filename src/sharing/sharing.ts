import { Factory, NamedProvider } from '../factory';

export interface SharingProvider extends NamedProvider {
  split(secret: Uint8Array, n: number, t: number): Promise<Uint8Array[]>;
  combine(shares: Uint8Array[]): Promise<Uint8Array>;
}

export const SharingFactory = new Factory<SharingProvider>('Sharing');
