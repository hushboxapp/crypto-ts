import { describe, it, expect } from 'vitest';
import { Argon2Provider } from '../../src/hashing/argon2';
import { NativeProvider } from '../../src/randomness/native';

describe('Argon2Provider', () => {
  // Use lower parameters for faster tests
  const options = {
    iterations: 1,
    memorySize: 1024, // 1 MB
    parallelism: 1,
    hashLength: 32
  };
  const provider = new Argon2Provider(options);
  const randomness = new NativeProvider();

  it('should derive a key from a password and salt', async () => {
    const password = 'my-secure-password';
    const salt = randomness.generate(16);

    const key = await provider.derive(password, salt);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it('should produce the same key for the same password and salt', async () => {
    const password = 'my-secure-password';
    const salt = randomness.generate(16);

    const key1 = await provider.derive(password, salt);
    const key2 = await provider.derive(password, salt);
    expect(key1).toEqual(key2);
  });

  it('should produce different keys for different passwords', async () => {
    const salt = randomness.generate(16);

    const key1 = await provider.derive('pass1', salt);
    const key2 = await provider.derive('pass2', salt);
    expect(key1).not.toEqual(key2);
  });

  it('should produce different keys for different salts', async () => {
    const password = 'password';
    const salt1 = randomness.generate(16);
    const salt2 = randomness.generate(16);

    const key1 = await provider.derive(password, salt1);
    const key2 = await provider.derive(password, salt2);
    expect(key1).not.toEqual(key2);
  });
});
