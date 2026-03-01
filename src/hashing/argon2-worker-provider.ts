import { HashingProvider } from './hashing';
import { Argon2Options, DEFAULT_ARGON2_OPTIONS } from './argon2';

/**
 * An Argon2id HashingProvider that runs in a Web Worker to avoid blocking the UI thread.
 */
export class Argon2WorkerProvider implements HashingProvider {
  readonly name = 'argon2id-worker';
  private nextId = 0;
  private pendingRequests = new Map<
    number,
    { resolve: (value: Uint8Array) => void; reject: (reason: Error) => void }
  >();
  private worker: Worker;

  /**
   * @param workerFactory A function that returns a new Worker instance.
   * Example: () => new Worker(new URL('./argon2.worker.js', import.meta.url))
   * @param options Argon2id parameters.
   */
  constructor(
    private workerFactory: () => Worker,
    private options: Partial<Argon2Options> = {},
  ) {
    this.worker = this.workerFactory();
    this.worker.onmessage = this.handleMessage.bind(this);
  }

  async derive(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const id = this.nextId++;
    const params = this.getParams();

    return new Promise((resolve, reject) => {
      // @ts-ignore
      this.pendingRequests.set(id, { resolve, reject });
      this.worker.postMessage({
        id,
        password,
        salt,
        options: params,
      });
    });
  }

  getParams(): Record<string, unknown> {
    return { ...DEFAULT_ARGON2_OPTIONS, ...this.options };
  }

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
   * Terminate the background worker.
   */
  terminate() {
    this.worker.terminate();
  }
}
