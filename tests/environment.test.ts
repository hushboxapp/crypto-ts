import { describe, it, expect, vi } from 'vitest';
import { AESGCMProvider } from '../src/encryption/aes-gcm';
import { NativeProvider } from '../src/randomness/native';
import { SecureContextError, CryptoApiUnavailableError } from '../src/errors';

describe('Environment-dependent branches', () => {
  it('AESGCMProvider should throw SecureContextError when isSecureContext is false', async () => {
    // Mock isSecureContext
    const originalIsSecureContext = globalThis.isSecureContext;
    Object.defineProperty(globalThis, 'isSecureContext', {
      value: false,
      configurable: true
    });

    const provider = new AESGCMProvider();
    await expect(provider.encrypt(new Uint8Array(1), new Uint8Array(32), new Uint8Array(12)))
      .rejects.toThrow(SecureContextError);

    // Restore
    Object.defineProperty(globalThis, 'isSecureContext', {
      value: originalIsSecureContext,
      configurable: true
    });
  });

  it('NativeProvider should throw SecureContextError when isSecureContext is false', () => {
    // Mock isSecureContext
    const originalIsSecureContext = globalThis.isSecureContext;
    Object.defineProperty(globalThis, 'isSecureContext', {
      value: false,
      configurable: true
    });

    const provider = new NativeProvider();
    expect(() => provider.generate(16)).toThrow(SecureContextError);

    // Restore
    Object.defineProperty(globalThis, 'isSecureContext', {
      value: originalIsSecureContext,
      configurable: true
    });
  });

  it('NativeProvider should throw CryptoApiUnavailableError when getRandomValues is missing', () => {
    const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', {
      value: {},
      configurable: true,
      writable: true,
    });

    const provider = new NativeProvider();
    expect(() => provider.generate(16)).toThrow(CryptoApiUnavailableError);

    if (originalDescriptor) {
      Object.defineProperty(globalThis, 'crypto', originalDescriptor);
    }
  });

  it('AESGCMProvider should throw CryptoApiUnavailableError when crypto is missing', async () => {
    // Mock the private getSubtleCrypto method
    const spy = vi.spyOn(AESGCMProvider.prototype as any, 'getSubtleCrypto')
      .mockImplementation(() => {
        throw new CryptoApiUnavailableError();
      });

    const provider = new AESGCMProvider();
    await expect(provider.encrypt(new Uint8Array(1), new Uint8Array(32), new Uint8Array(12)))
      .rejects.toThrow(CryptoApiUnavailableError);

    spy.mockRestore();
  });
});
