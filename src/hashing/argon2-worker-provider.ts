import { HashingProvider } from './hashing';
import { Argon2Options, DEFAULT_ARGON2_OPTIONS } from './argon2';
import { WorkerError, WorkerTimeoutError, WorkerTerminatedError } from '../errors';

/**
 * Default per-request timeout for worker derivations (60 seconds).
 * Argon2id with maximal recommended parameters runs well under this on commodity hardware.
 */
export const DEFAULT_WORKER_TIMEOUT_MS = 60_000;

interface PendingRequest {
  resolve: (value: Uint8Array) => void;
  reject: (reason: Error) => void;
  timeoutHandle: ReturnType<typeof setTimeout> | null;
}

/**
 * Configuration options for {@link Argon2WorkerProvider}.
 */
export interface Argon2WorkerProviderOptions {
  /** Argon2id parameter overrides applied to every request. */
  argon2?: Partial<Argon2Options>;
  /**
   * Per-request timeout in milliseconds. A request that does not complete within
   * this window is rejected with {@link WorkerTimeoutError}. Pass `0` to disable.
   * Defaults to {@link DEFAULT_WORKER_TIMEOUT_MS}.
   */
  timeoutMs?: number;
}

/**
 * An implementation of HashingProvider that runs Argon2id in a background Web Worker.
 * This is the recommended provider for browser environments to ensure the UI remains responsive
 * during the computationally expensive key derivation process.
 *
 * The provider hardens itself against three failure modes:
 *  - worker crashes (uncaught error in worker context) → {@link WorkerError}
 *  - hung work (e.g. broken WASM, deadlock)            → {@link WorkerTimeoutError}
 *  - use after termination                              → {@link WorkerTerminatedError}
 */
export class Argon2WorkerProvider implements HashingProvider {
  /** The unique identifier for this provider. */
  readonly name = 'argon2id-worker';
  private nextId = 0;
  private pendingRequests = new Map<number, PendingRequest>();
  private worker: Worker;
  private fatalError: Error | null = null;
  private terminated = false;
  private readonly timeoutMs: number;
  private readonly options: Partial<Argon2Options>;

  /**
   * @param workerFactory - A function that returns a new Worker instance.
   * Typically: `() => new Worker(new URL('./argon2.worker.js', import.meta.url))`
   * @param optionsOrArgon2 - Either a {@link Argon2WorkerProviderOptions} bundle or, for
   * backward compatibility, a plain {@link Argon2Options} partial.
   */
  constructor(
    private workerFactory: () => Worker,
    optionsOrArgon2: Argon2WorkerProviderOptions | Partial<Argon2Options> = {},
  ) {
    const isWrapped = 'argon2' in optionsOrArgon2 || 'timeoutMs' in optionsOrArgon2;
    const wrapped: Argon2WorkerProviderOptions = isWrapped
      ? (optionsOrArgon2 as Argon2WorkerProviderOptions)
      : { argon2: optionsOrArgon2 as Partial<Argon2Options> };

    this.options = wrapped.argon2 ?? {};
    this.timeoutMs = wrapped.timeoutMs ?? DEFAULT_WORKER_TIMEOUT_MS;

    this.worker = this.workerFactory();
    this.worker.onmessage = this.handleMessage.bind(this);
    this.worker.onerror = this.handleFatal.bind(this);
    this.worker.onmessageerror = this.handleFatal.bind(this);
  }

  /**
   * Offloads key derivation to the background worker.
   *
   * @param password - The user password (string or raw bytes).
   * @param salt - The cryptographic salt.
   * @param params - Optional Argon2id parameters that override the provider defaults for this call.
   * @returns A promise that resolves when the worker finishes hashing.
   */
  async derive(
    password: string | Uint8Array,
    salt: Uint8Array,
    params?: Record<string, unknown>,
  ): Promise<Uint8Array> {
    if (this.fatalError) {
      throw new WorkerError(this.fatalError.message);
    }
    if (this.terminated) {
      throw new WorkerTerminatedError();
    }

    const id = this.nextId++;
    const merged = { ...this.getParams(), ...params };

    return new Promise<Uint8Array>((resolve, reject) => {
      const timeoutHandle =
        this.timeoutMs > 0
          ? setTimeout(() => {
              if (this.pendingRequests.delete(id)) {
                reject(new WorkerTimeoutError(this.timeoutMs));
              }
            }, this.timeoutMs)
          : null;

      this.pendingRequests.set(id, { resolve, reject, timeoutHandle });
      this.worker.postMessage({
        id,
        password,
        salt,
        options: merged,
      });
    });
  }

  /**
   * Returns the current Argon2id configuration.
   */
  getParams(): Record<string, unknown> {
    return { ...DEFAULT_ARGON2_OPTIONS, ...this.options };
  }

  /**
   * Internal message handler for worker communication.
   */
  private handleMessage(e: MessageEvent) {
    const { id, result, error } = e.data;
    const request = this.pendingRequests.get(id);

    if (!request) return;

    this.pendingRequests.delete(id);
    if (request.timeoutHandle !== null) clearTimeout(request.timeoutHandle);

    if (error) {
      request.reject(new Error(error));
    } else {
      request.resolve(result);
    }
  }

  /**
   * Handles fatal worker events (uncaught errors, structured-clone failures).
   * Rejects all pending requests and renders the provider unusable; callers must
   * construct a fresh instance to resume hashing.
   */
  private handleFatal(event: ErrorEvent | MessageEvent) {
    const message =
      event instanceof ErrorEvent && event.message
        ? event.message
        : 'Worker terminated unexpectedly.';
    this.fatalError = new WorkerError(message);
    this.rejectAllPending(this.fatalError);
    this.worker.onerror = null;
    this.worker.onmessageerror = null;
    try {
      this.worker.terminate();
    } catch {
      // Ignore: worker may already be dead.
    }
  }

  private rejectAllPending(reason: Error): void {
    for (const [id, request] of this.pendingRequests) {
      if (request.timeoutHandle !== null) clearTimeout(request.timeoutHandle);
      request.reject(reason);
      this.pendingRequests.delete(id);
    }
  }

  /**
   * Terminates the background worker thread and rejects any in-flight requests.
   * After calling this, the provider can no longer be used.
   */
  terminate() {
    this.terminated = true;
    this.rejectAllPending(new WorkerTerminatedError());
    this.worker.terminate();
  }
}
