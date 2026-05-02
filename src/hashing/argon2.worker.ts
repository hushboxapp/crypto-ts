import { argon2id } from 'hash-wasm';

/**
 * Web Worker for Argon2id hashing.
 */
self.onmessage = async (e: MessageEvent) => {
  // Dedicated workers only receive messages from their creating context.
  // Browsers set `event.origin` to the empty string for same-origin parents,
  // or to the parent's origin otherwise. Reject anything else.
  if (e.origin !== '' && e.origin !== self.location.origin) {
    return;
  }
  const { id, password, salt, options } = e.data;
  try {
    const result = await argon2id({
      ...options,
      password,
      salt,
      outputType: 'binary',
    });
    const resultData = result as Uint8Array;
    (self as { postMessage(msg: unknown, transfer: Transferable[]): void }).postMessage(
      { id, result: resultData },
      [resultData.buffer as ArrayBuffer],
    );
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    self.postMessage({ id, error: message });
  }
};
