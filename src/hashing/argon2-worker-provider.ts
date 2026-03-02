import { HashingProvider } from './hashing';
import { Argon2Options, DEFAULT_ARGON2_OPTIONS } from './argon2';

/**
 * An implementation of HashingProvider that runs Argon2id in a background Web Worker.
 * This is the recommended provider for browser environments to ensure the UI remains responsive
 * during the computationally expensive key derivation process.
 */
export class Argon2WorkerProvider implements HashingProvider {
  /** The unique identifier for this provider. */
  readonly name = 'argon2id-worker';
  private nextId = 0;
  private pendingRequests = new Map<
    number,
    { resolve: (value: Uint8Array) => void; reject: (reason: Error) => void }
  >();
  private worker: Worker;

  /**
   * @param workerFactory - A function that returns a new Worker instance.
   * Typically: `() => new Worker(new URL('./argon2.worker.js', import.meta.url))`
   * @param options - Optional custom parameters for Argon2id.
   */
  constructor(
    private workerFactory: () => Worker,
    private options: Partial<Argon2Options> = {},
  ) {
    this.worker = this.workerFactory();
    this.worker.onmessage = this.handleMessage.bind(this);
  }

  /**
   * Offloads key derivation to the background worker.
   *
   * @param password - The user password (string or raw bytes).
   * @param salt - The cryptographic salt.
   * @returns A promise that resolves when the worker finishes hashing.
   */
  async derive(password: string | Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
    const id = this.nextId++;
    const params = this.getParams();

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });
      this.worker.postMessage({
        id,
        password,
        salt,
        options: params,
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

    if (request) {
      this.pendingRequests.delete(id);
      if (error) {
        request.reject(new Error(error));
      } else {
        request.resolve(result);
      }
    }
  }

  /**
   * Terminates the background worker thread.
   * After calling this, the provider can no longer be used.
   */
  terminate() {
    this.worker.terminate();
  }
}
