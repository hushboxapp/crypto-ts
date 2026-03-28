# 🔐 @hushboxapp/crypto

[![Build & Tests](https://github.com/hushboxapp/crypto-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/hushboxapp/crypto-ts/actions/workflows/ci.yml)
[![NPM Version](https://img.shields.io/npm/v/@hushboxapp/crypto.svg)](https://www.npmjs.com/package/@hushboxapp/crypto)
[![Release Status](https://github.com/hushboxapp/crypto-ts/actions/workflows/release-please.yml/badge.svg)](https://github.com/hushboxapp/crypto-ts/actions/workflows/release-please.yml)

A browser-compatible TypeScript library for advanced cryptographic operations.

## Features

- **Modern Cryptography**: Built on industry-standard AES-GCM (256-bit) and Argon2id.
- **Multi-Password Protection**: Secure your keys with an M-of-N password scheme using Shamir's Secret Sharing.
- **Browser & Node.js Compatible**: Seamlessly works in modern browsers (via Web Crypto API) and Node.js environments.
- **High-Performance Hashing**: Argon2id implementation via WebAssembly (`hash-wasm`) for strong key derivation.

## Installation

```bash
npm install @hushboxapp/crypto
```

## Quick Start

The core workflow involves creating a master `Key`, protecting it with one or more passwords to get an `EncryptedKey`, and using the `Key` to encrypt data into a `Document`.

### Encrypting Data

```typescript
import { Key, Document } from '@hushboxapp/crypto';

// 1. Generate a new random 256-bit master key
const masterKey = Key.generate();

// 2. Protect the key with passwords (M-of-N)
// In this example, we require any 2 out of 3 passwords to unlock the key
const passwords = ['p4ssw0rd1', 'secret-phrase', 'another-pass'];
const threshold = 2;
const encryptedKey = await masterKey.encrypt(passwords, threshold);

// 3. Encrypt sensitive data
const data = new TextEncoder().encode('Hello, Hushbox!');
const encryptedDocument = await Document.encrypt(data, masterKey);

// 4. Serialize for storage or transmission
const serializedKey = encryptedKey.encode();
const serializedDoc = encryptedDocument.encode();
```

### Decrypting Data

```typescript
import { EncryptedKey, Document } from '@hushboxapp/crypto';

// 1. Restore objects from serialized strings
const restoredKey = EncryptedKey.decode(serializedKey);
const restoredDoc = Document.decode(serializedDoc);

// 2. Unlock the master key using the required number of passwords
const unlockedKey = await restoredKey.decrypt(['p4ssw0rd1', 'another-pass']);

// 3. Decrypt the document content
const decryptedData = await restoredDoc.decrypt(unlockedKey);
console.log(new TextDecoder().decode(decryptedData)); // "Hello, Hushbox!"
```
