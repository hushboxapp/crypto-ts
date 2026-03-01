import { describe, it, expect } from 'vitest';
import { Argon2WorkerProvider } from '../../src/hashing/argon2-worker-provider';
import { NativeProvider } from '../../src/randomness/native';

describe('Argon2WorkerProvider', () => {
  // We only run this in the browser because creating Web Workers from TS files 
  // is natively supported in many modern build tools/environments that Vitest Browser emulates.
  // In Node.js, this would require a different setup.
  
  it('should derive a key using a worker', { skip: typeof window === 'undefined' }, async () => {
    const workerFactory = () => new Worker(new URL('../../src/hashing/argon2.worker.ts', import.meta.url), { type: 'module' });
    
    // Use lower parameters for faster tests
    const options = {
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 32
    };
    
    const provider = new Argon2WorkerProvider(workerFactory, options);
    const randomness = new NativeProvider();
    const password = 'worker-password';
    const salt = randomness.generate(16);

    const key = await provider.derive(password, salt);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
    
    provider.terminate();
  });
});
