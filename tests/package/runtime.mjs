import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import * as esm from '@hushboxapp/crypto';

const require = createRequire(import.meta.url);
const cjs = require('@hushboxapp/crypto');
assert.deepEqual(Object.keys(esm).sort(), Object.keys(cjs).sort());

for (const api of [esm, cjs]) {
  // Registration side effects must survive tree shaking in both formats.
  const cipher = api.EncryptionFactory.getProvider('aes-gcm');
  const key = new Uint8Array(32).fill(1);
  const iv = new Uint8Array(12).fill(2);
  const plaintext = new TextEncoder().encode('packed package');
  const ciphertext = await cipher.encrypt(plaintext, key, iv);
  assert.deepEqual(await cipher.decrypt(ciphertext, key, iv), plaintext);
  assert.ok(api.HashingFactory.getProvider('argon2id'));
}

// Exercise each emitted worker module with the Web Worker message interface.
const dist = dirname(require.resolve('@hushboxapp/crypto'));
for (const extension of ['js', 'mjs']) {
  let response;
  globalThis.self = {
    location: { origin: 'https://package.test' },
    postMessage(message) {
      response = message;
    },
  };
  try {
    await import(pathToFileURL(join(dist, `hashing/argon2.worker.${extension}`)).href);
    const salt = new Uint8Array(16).fill(3);
    const options = { parallelism: 1, iterations: 1, memorySize: 64, hashLength: 32 };
    await self.onmessage({
      origin: '',
      data: { id: 1, password: 'package-test', salt, options },
    });
    assert.equal(response.id, 1);
    assert.equal(response.error, undefined);
    assert.deepEqual(response.result, await esm.deriveKey('package-test', { ...options, salt }));
  } finally {
    delete globalThis.self;
  }
}

console.log('Packed ESM/CommonJS imports, provider registration, encryption, and workers passed.');
