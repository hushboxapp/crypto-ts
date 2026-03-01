import { describe, it, expect } from 'vitest';
import { NativeProvider } from '../../src/randomness/native';

describe('NativeProvider', () => {
  const provider = new NativeProvider();

  it('should generate random bytes of correct length', () => {
    const length = 32;
    const bytes = provider.generate(length);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(length);
  });

  it('should generate unique values', () => {
    const bytes1 = provider.generate(32);
    const bytes2 = provider.generate(32);
    expect(bytes1).not.toEqual(bytes2);
  });
});
