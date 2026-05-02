import { describe, it, expect } from 'vitest';
import { ShamirProvider } from '../../src/sharing/shamir';

describe('ShamirProvider', () => {
  const provider = new ShamirProvider();

  it('should split and combine secret correctly', async () => {
    const secret = new TextEncoder().encode('Super secret password');
    const n = 5;
    const t = 3;

    const shares = await provider.split(secret, n, t);
    expect(shares.length).toBe(n);

    // Recombine with exactly threshold
    const reconstructed = await provider.combine(shares.slice(0, t));
    expect(reconstructed).toEqual(secret);
    expect(new TextDecoder().decode(reconstructed)).toBe('Super secret password');

    // Recombine with more than threshold
    const reconstructedMore = await provider.combine(shares.slice(0, t + 1));
    expect(reconstructedMore).toEqual(secret);
  });

  it('should split and combine with threshold of 1', async () => {
    const secret = new TextEncoder().encode('threshold-1 secret');
    const shares = await provider.split(secret, 3, 1);
    expect(shares.length).toBe(3);
    const reconstructed = await provider.combine([shares[0]]);
    expect(reconstructed).toEqual(secret);
  });

  it('should fail to recombine with less than threshold', async () => {
    const secret = new TextEncoder().encode('Super secret password');
    const n = 5;
    const t = 3;

    const shares = await provider.split(secret, n, t);
    
    // Recombine with less than threshold - depending on the implementation it might return wrong data or fail
    // shamir-secret-sharing package usually returns wrong data if threshold is not met
    const reconstructed = await provider.combine(shares.slice(0, t - 1));
    expect(reconstructed).not.toEqual(secret);
  });

  it('should throw error for invalid split parameters', async () => {
    const { InvalidThresholdError, InvalidShareCountError, EmptyDataError } = await import('../../src/errors');
    const secret = new TextEncoder().encode('Secret');
    
    await expect(provider.split(secret, 5, 6)).rejects.toThrow(InvalidThresholdError);
    await expect(provider.split(secret, 0, 0)).rejects.toThrow(InvalidShareCountError);
    await expect(provider.split(new Uint8Array(0), 5, 3)).rejects.toThrow(EmptyDataError);
  });
});
