import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  Argon2WorkerProvider,
  DEFAULT_WORKER_TIMEOUT_MS,
  type Argon2WorkerProviderOptions,
} from '../../src/hashing/argon2-worker-provider';
import { DEFAULT_ARGON2_OPTIONS, type Argon2Options } from '../../src/hashing/argon2';
import { WorkerError, WorkerTerminatedError, WorkerTimeoutError } from '../../src/errors';

describe('Argon2WorkerProvider request lifecycle', () => {
  const salt = new Uint8Array(16);
  const providers: Argon2WorkerProvider[] = [];

  function setup(options?: Argon2WorkerProviderOptions | Partial<Argon2Options>) {
    const worker = {
      postMessage: vi.fn(),
      terminate: vi.fn(),
      onmessage: null as ((event: MessageEvent) => void) | null,
      onerror: null as ((event: ErrorEvent) => void) | null,
      onmessageerror: null as ((event: MessageEvent) => void) | null,
    };
    const provider = new Argon2WorkerProvider(() => worker as unknown as Worker, options);
    providers.push(provider);
    const respond = (data: unknown) => worker.onmessage!(new MessageEvent('message', { data }));
    return { worker, provider, respond };
  }

  beforeEach(() => {
    vi.useFakeTimers();
    // Node provides MessageEvent but not the browser's ErrorEvent constructor.
    if (typeof ErrorEvent === 'undefined') {
      vi.stubGlobal(
        'ErrorEvent',
        class extends Event {
          readonly message: string;
          constructor(type: string, init: ErrorEventInit = {}) {
            super(type, init);
            this.message = init.message ?? '';
          }
        },
      );
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
    for (const provider of providers.splice(0)) provider.terminate();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('sends default parameters and returns the worker result', async () => {
    const { provider, worker, respond } = setup();
    const pending = provider.derive('password', salt);
    expect(worker.postMessage).toHaveBeenCalledExactlyOnceWith({
      id: 0,
      password: 'password',
      salt,
      options: DEFAULT_ARGON2_OPTIONS,
    });
    expect(vi.getTimerCount()).toBe(1);

    const result = new Uint8Array([1, 2, 3]);
    respond({ id: 0, result });
    await expect(pending).resolves.toEqual(result);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([{ iterations: 2, memorySize: 1024 }, { argon2: { iterations: 2, memorySize: 1024 } }])(
    'merges legacy and wrapped options with per-request overrides: %j',
    async (options) => {
      const { provider, worker, respond } = setup(options);
      const password = new Uint8Array([4, 5]);
      const pending = provider.derive(password, salt, { iterations: 3 });
      expect(worker.postMessage).toHaveBeenCalledExactlyOnceWith({
        id: 0,
        password,
        salt,
        options: { ...DEFAULT_ARGON2_OPTIONS, memorySize: 1024, iterations: 3 },
      });
      const params = provider.getParams();
      expect(params.iterations).toBe(2);
      params.iterations = 99;
      expect(provider.getParams().iterations).toBe(2);
      respond({ id: 0, result: new Uint8Array([1]) });
      await expect(pending).resolves.toEqual(new Uint8Array([1]));
    },
  );

  it('matches out-of-order responses to requests and ignores unknown or duplicate responses', async () => {
    const { provider, worker, respond } = setup();
    const first = provider.derive('first', salt);
    const second = provider.derive('second', salt);
    const [firstId, secondId] = worker.postMessage.mock.calls.map(([request]) => request.id);
    expect(firstId).not.toBe(secondId);
    respond({ id: 999, result: new Uint8Array([9]) });
    expect(vi.getTimerCount()).toBe(2);
    respond({ id: secondId, result: new Uint8Array([2]) });
    respond({ id: secondId, error: 'duplicate response' });
    respond({ id: firstId, result: new Uint8Array([1]) });
    await expect(Promise.all([first, second])).resolves.toEqual([
      new Uint8Array([1]),
      new Uint8Array([2]),
    ]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('rejects a failed derivation without affecting other requests or future work', async () => {
    const { provider, respond } = setup();
    const failed = provider.derive('invalid', salt);
    const failure = expect(failed).rejects.toThrow('Invalid Argon2 parameters');
    const successful = provider.derive('valid', salt);
    respond({ id: 0, error: 'Invalid Argon2 parameters' });
    await failure;
    expect(vi.getTimerCount()).toBe(1);
    respond({ id: 1, result: new Uint8Array([2]) });
    await expect(successful).resolves.toEqual(new Uint8Array([2]));
    const next = provider.derive('next', salt);
    respond({ id: 2, result: new Uint8Array([3]) });
    await expect(next).resolves.toEqual(new Uint8Array([3]));
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([undefined, 25])(
    'times out stalled requests and accepts new work (timeout %s)',
    async (timeoutMs) => {
      const { provider, respond } = setup(timeoutMs === undefined ? undefined : { timeoutMs });
      const pending = provider.derive('stalled', salt);
      const failure = expect(pending).rejects.toThrow(WorkerTimeoutError);
      await vi.advanceTimersByTimeAsync(timeoutMs ?? DEFAULT_WORKER_TIMEOUT_MS);
      await failure;
      expect(vi.getTimerCount()).toBe(0);

      const next = provider.derive('next', salt);
      respond({ id: 0, result: new Uint8Array([9]) });
      expect(vi.getTimerCount()).toBe(1);
      respond({ id: 1, result: new Uint8Array([1]) });
      await expect(next).resolves.toEqual(new Uint8Array([1]));
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it('allows an untimed request to finish after the default timeout', async () => {
    const { provider, respond } = setup({ timeoutMs: 0 });
    const pending = provider.derive('password', salt);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(DEFAULT_WORKER_TIMEOUT_MS + 1);
    respond({ id: 0, result: new Uint8Array([1]) });
    await expect(pending).resolves.toEqual(new Uint8Array([1]));
  });

  it.each(['error', 'empty-error', 'messageerror', 'already-dead'])(
    'rejects all pending and future requests on a fatal worker event: %s',
    async (kind) => {
      const { provider, worker } = setup({ timeoutMs: kind === 'messageerror' ? 0 : 100 });
      const pending = [provider.derive('first', salt), provider.derive('second', salt)];
      const failures = pending.map((request) => expect(request).rejects.toThrow(WorkerError));
      if (kind === 'already-dead') {
        worker.terminate.mockImplementationOnce(() => {
          throw new Error('Already dead');
        });
      }
      const message = kind === 'error' || kind === 'already-dead' ? 'Worker crash' : '';
      if (kind === 'messageerror') {
        worker.onmessageerror!(new MessageEvent('messageerror'));
      } else {
        worker.onerror!(new ErrorEvent('error', { message }));
      }
      await Promise.all(failures);
      expect(vi.getTimerCount()).toBe(0);
      expect(worker.terminate).toHaveBeenCalledOnce();
      expect(worker.onerror).toBeNull();
      expect(worker.onmessageerror).toBeNull();
      await expect(provider.derive('future', salt)).rejects.toThrow(
        message || 'Worker terminated unexpectedly.',
      );
      expect(worker.postMessage).toHaveBeenCalledTimes(2);
    },
  );

  it.each([0, 100])(
    'terminates pending requests and prevents new work (timeout %s)',
    async (timeoutMs) => {
      const { provider, worker, respond } = setup({ timeoutMs });
      const pending = [provider.derive('first', salt), provider.derive('second', salt)];
      const failures = pending.map((request) =>
        expect(request).rejects.toThrow(WorkerTerminatedError),
      );
      provider.terminate();
      await Promise.all(failures);
      expect(vi.getTimerCount()).toBe(0);
      expect(worker.terminate).toHaveBeenCalledOnce();
      respond({ id: 0, result: new Uint8Array([1]) });
      await expect(provider.derive('future', salt)).rejects.toThrow(WorkerTerminatedError);
      expect(worker.postMessage).toHaveBeenCalledTimes(2);
    },
  );
});
