import { Factory, NamedProvider } from '../factory';

export interface RandomnessProvider extends NamedProvider {
  generate(length: number): Uint8Array;
}

export const RandomnessFactory = new Factory<RandomnessProvider>('Randomness');
