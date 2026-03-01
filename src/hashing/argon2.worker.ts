import { argon2id } from 'hash-wasm';

/**
 * Web Worker for Argon2id hashing.
 */
self.onmessage = async (e: MessageEvent) => {
  const { id, password, salt, options } = e.data;
  try {
    const result = await argon2id({
      ...options,
      password,
      salt,
      outputType: 'binary',
    });
    // @ts-ignore
    self.postMessage({ id, result }, [result.buffer]);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    self.postMessage({ id, error: message });
  }
};
