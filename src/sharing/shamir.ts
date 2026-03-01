import { split, combine } from 'shamir-secret-sharing';
import { SharingProvider, SharingFactory } from './sharing';
import { InvalidThresholdError, InvalidShareCountError, EmptyDataError } from '../errors';

export class ShamirProvider implements SharingProvider {
  readonly name = 'shamir';
  async split(secret: Uint8Array, n: number, t: number): Promise<Uint8Array[]> {
    if (secret.length === 0) {
      throw new EmptyDataError('Secret material cannot be empty.');
    }
    if (n < 1) {
      throw new InvalidShareCountError();
    }
    if (t > n || t < 1) {
      throw new InvalidThresholdError();
    }
    return await split(secret, n, t);
  }

  async combine(shares: Uint8Array[]): Promise<Uint8Array> {
    return await combine(shares);
  }
}

SharingFactory.addProvider(new ShamirProvider());
