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
    
    expect(provider.getParams().iterations).toBe(options.iterations);
    
    provider.terminate();
  });

  it('should ignore messages from untrusted origins', { skip: typeof window === 'undefined' }, async () => {
    const previousOnMessage = self.onmessage;
    const previousPostMessage = self.postMessage;

    await import('../../src/hashing/argon2.worker');
    const handler = self.onmessage;
    expect(typeof handler).toBe('function');

    const posted: unknown[] = [];
    self.postMessage = ((msg: unknown) => {
      posted.push(msg);
    }) as typeof self.postMessage;

    try {
      const event = new MessageEvent('message', {
        data: {
          id: 42,
          password: 'attacker-password',
          salt: new Uint8Array(16),
          options: { iterations: 1, memorySize: 1024, parallelism: 1, hashLength: 32 },
        },
        origin: 'https://evil.example.com',
      });

      await handler!.call(self, event);
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(posted).toHaveLength(0);
    } finally {
      self.postMessage = previousPostMessage;
      self.onmessage = previousOnMessage;
    }
  });

  it('should reject pending requests when worker emits onerror', { skip: typeof window === 'undefined' }, async () => {
    const { WorkerError } = await import('../../src/errors');

    const mockWorker: any = {
      postMessage: () => {},
      terminate: () => {},
      onmessage: null,
      onerror: null,
      onmessageerror: null,
    };

    const provider = new Argon2WorkerProvider(() => mockWorker as Worker);
    const randomness = new NativeProvider();
    const salt = randomness.generate(16);

    const inflight = provider.derive('password', salt);

    // Simulate an uncaught error inside the worker thread.
    const errorEvent = new ErrorEvent('error', { message: 'Worker crash' });
    mockWorker.onerror!(errorEvent);

    await expect(inflight).rejects.toThrow(WorkerError);
    await expect(provider.derive('password', salt)).rejects.toThrow(WorkerError);
  });

  it('should reject requests that exceed the per-request timeout', { skip: typeof window === 'undefined' }, async () => {
    const { WorkerTimeoutError } = await import('../../src/errors');

    const mockWorker: any = {
      postMessage: () => {
        // Never respond — exercise the timeout path.
      },
      terminate: () => {},
      onmessage: null,
      onerror: null,
      onmessageerror: null,
    };

    const provider = new Argon2WorkerProvider(() => mockWorker as Worker, {
      timeoutMs: 25,
    });
    const randomness = new NativeProvider();
    const salt = randomness.generate(16);

    await expect(provider.derive('password', salt)).rejects.toThrow(WorkerTimeoutError);
  });

  it('should reject in-flight and future requests after terminate()', { skip: typeof window === 'undefined' }, async () => {
    const { WorkerTerminatedError } = await import('../../src/errors');

    const mockWorker: any = {
      postMessage: () => {},
      terminate: () => {},
      onmessage: null,
      onerror: null,
      onmessageerror: null,
    };

    const provider = new Argon2WorkerProvider(() => mockWorker as Worker);
    const randomness = new NativeProvider();
    const salt = randomness.generate(16);

    const inflight = provider.derive('password', salt);
    provider.terminate();

    await expect(inflight).rejects.toThrow(WorkerTerminatedError);
    await expect(provider.derive('password', salt)).rejects.toThrow(WorkerTerminatedError);
  });

  it('should handle worker errors', { skip: typeof window === 'undefined' }, async () => {
    // Mock worker that returns an error
    const mockWorker = {
      postMessage: function(data: any) {
        setTimeout(() => {
          if (this.onmessage) {
            this.onmessage({
              data: {
                id: data.id,
                error: 'Mock Worker Error'
              }
            } as MessageEvent);
          }
        }, 10);
      },
      terminate: () => {},
      onmessage: null as ((e: MessageEvent) => void) | null
    };
    
    const workerFactory = () => mockWorker as unknown as Worker;
    const provider = new Argon2WorkerProvider(workerFactory);
    const randomness = new NativeProvider();
    const salt = randomness.generate(16);

    await expect(provider.derive('password', salt)).rejects.toThrow('Mock Worker Error');
  });
});
