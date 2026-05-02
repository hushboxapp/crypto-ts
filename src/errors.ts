/**
 * Base class for all library-specific errors.
 */
export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when decryption fails (e.g., incorrect password or corrupted data).
 */
export class DecryptionError extends CryptoError {
  constructor(message = 'Decryption failed. Check your passwords or data integrity.') {
    super(message);
  }
}

/**
 * Thrown when an invalid threshold is provided for M-of-N operations.
 */
export class InvalidThresholdError extends CryptoError {
  constructor(
    message = 'Invalid threshold: must be an integer between 1 and the number of shares/passwords.',
  ) {
    super(message);
  }
}

/**
 * Thrown when an invalid number of shares is requested.
 */
export class InvalidShareCountError extends CryptoError {
  constructor(message = 'Invalid share count: must be an integer between 1 and 255.') {
    super(message);
  }
}

/**
 * Thrown when insufficient shares or passwords are provided to reconstruct a secret.
 */
export class InsufficientSharesError extends CryptoError {
  constructor(unlocked: number, required: number) {
    super(`Insufficient correct components: unlocked ${unlocked}/${required} required.`);
  }
}

/**
 * Thrown when a requested provider is not found in a factory.
 */
export class ProviderNotFoundError extends CryptoError {
  constructor(type: string, name: string) {
    super(`${type} provider '${name}' not found.`);
  }
}

/**
 * Thrown when the environment does not support secure cryptographic operations.
 */
export class SecureContextError extends CryptoError {
  constructor(
    message = 'Web Crypto API is only available in Secure Contexts (HTTPS or localhost).',
  ) {
    super(message);
  }
}

/**
 * Thrown when the Web Crypto API is not found in the current environment.
 */
export class CryptoApiUnavailableError extends CryptoError {
  constructor(message = 'Web Crypto API not available in this environment.') {
    super(message);
  }
}

/**
 * Thrown when key material is invalid or of an incorrect length.
 */
export class InvalidKeyError extends CryptoError {
  constructor(message = 'Key must be exactly 256 bits (32 bytes).') {
    super(message);
  }
}

/**
 * Thrown when an unsupported version of an encoded object is detected.
 */
export class UnsupportedVersionError extends CryptoError {
  constructor(version: number | string, supported: number | string) {
    super(`Unsupported version: ${version}. Supported version is ${supported}.`);
  }
}

/**
 * Thrown when an empty Uint8Array is provided where data was expected.
 */
export class EmptyDataError extends CryptoError {
  constructor(message = 'Operation cannot be performed with empty data.') {
    super(message);
  }
}

/**
 * Thrown when an empty passwords array is provided.
 */
export class EmptyPasswordsError extends CryptoError {
  constructor(message = 'At least one password must be provided.') {
    super(message);
  }
}

/**
 * Thrown when an empty key is provided.
 */
export class EmptyKeyError extends CryptoError {
  constructor(message = 'Key material cannot be empty.') {
    super(message);
  }
}

/**
 * Thrown when an empty IV is provided.
 */
export class EmptyIVError extends CryptoError {
  constructor(message = 'Initialization Vector (IV) cannot be empty.') {
    super(message);
  }
}

/**
 * Thrown when a background worker emits a fatal error (crash, uncaught exception,
 * or message deserialization failure). All in-flight requests are rejected with
 * this error and the provider is marked as unusable.
 */
export class WorkerError extends CryptoError {
  constructor(message = 'Worker terminated unexpectedly.') {
    super(message);
  }
}

/**
 * Thrown when a worker request exceeds its configured timeout.
 */
export class WorkerTimeoutError extends CryptoError {
  constructor(timeoutMs: number) {
    super(`Worker request timed out after ${timeoutMs}ms.`);
  }
}

/**
 * Thrown when a request is made to a worker that has been terminated or has
 * encountered a fatal error.
 */
export class WorkerTerminatedError extends CryptoError {
  constructor(message = 'Worker has been terminated and can no longer accept requests.') {
    super(message);
  }
}

/**
 * Thrown when a serialized envelope references a provider name that is not on
 * the caller-supplied allowlist. Defends against confused-deputy attacks where
 * a hostile module registers a provider under a known name and a tampered
 * envelope redirects decryption to it.
 */
export class DisallowedProviderError extends CryptoError {
  constructor(type: string, name: string, allowed: readonly string[]) {
    super(
      `${type} provider '${name}' is not allowed. Allowed: [${allowed.map((a) => `'${a}'`).join(', ')}].`,
    );
  }
}

/**
 * Thrown when an operation is attempted on a Key whose material has been
 * zeroed via {@link Key.dispose}.
 */
export class KeyDisposedError extends CryptoError {
  constructor(message = 'Key has been disposed; its material is no longer available.') {
    super(message);
  }
}

/**
 * Thrown when an encoding provider is given input it cannot decode (e.g.,
 * non-Base64 characters fed to {@link Base64Engine.decode}). Wraps host
 * runtime exceptions (DOMException, etc.) so callers only need to catch
 * library-domain errors.
 */
export class InvalidEncodingError extends CryptoError {
  constructor(encoding: string, cause?: unknown) {
    super(`Input is not a valid ${encoding} string.`);
    if (cause !== undefined) {
      (this as { cause?: unknown }).cause = cause;
    }
  }
}

/**
 * Thrown when decode input was successfully decoded from its encoding but
 * the resulting payload is not valid JSON (e.g., a Base64 string that decodes
 * to arbitrary text rather than a serialised envelope).
 */
export class InvalidFormatError extends CryptoError {
  constructor(message?: string, cause?: unknown) {
    super(message ?? 'Encoded data is not valid JSON.');
    if (cause !== undefined) {
      (this as { cause?: unknown }).cause = cause;
    }
  }
}
