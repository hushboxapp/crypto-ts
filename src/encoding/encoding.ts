import { Factory, NamedProvider } from '../factory';

export interface EncodingProvider extends NamedProvider {
  btoa(str: string): string;
  atob(b64: string): string;
}

export const EncodingFactory = new Factory<EncodingProvider>('Encoding');
