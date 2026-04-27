import { Base64Engine } from '../src/encoding/base64';
import { CryptoError } from '../src/errors';

const engine = new Base64Engine();

export function fuzz(data: Buffer): void {
  let mode: number;
  let payload: Buffer;
  if (data.length === 0) {
    mode = 0;
    payload = data;
  } else {
    mode = data[0] % 4;
    payload = data.subarray(1);
  }

  try {
    switch (mode) {
      case 0: {
        const bytes = new Uint8Array(payload);
        const encoded = engine.encode(bytes);
        const decoded = engine.decode(encoded);
        if (decoded.length !== bytes.length) {
          throw new Error(`round-trip length mismatch: ${decoded.length} != ${bytes.length}`);
        }
        for (let i = 0; i < bytes.length; i++) {
          if (decoded[i] !== bytes[i]) {
            throw new Error(`round-trip byte mismatch at index ${i}`);
          }
        }
        break;
      }
      case 1: {
        engine.decode(payload.toString('utf8'));
        break;
      }
      case 2: {
        const str = payload.toString('binary');
        const encoded = engine.btoa(str);
        const decoded = engine.atob(encoded);
        if (decoded !== str) {
          throw new Error('btoa/atob round-trip mismatch');
        }
        break;
      }
      case 3: {
        engine.atob(payload.toString('utf8'));
        break;
      }
    }
  } catch (e) {
    if (e instanceof CryptoError) return;
    if (e instanceof RangeError || e instanceof TypeError) return;
    throw e;
  }
}
