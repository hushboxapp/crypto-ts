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
  constructor(message = 'Invalid threshold: must be between 1 and the number of shares/passwords.') {
    super(message);
  }
}

/**
 * Thrown when an invalid number of shares is requested.
 */
export class InvalidShareCountError extends CryptoError {
  constructor(message = 'Invalid share count: must be at least 1.') {
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
  constructor(message = 'Web Crypto API is only available in Secure Contexts (HTTPS or localhost).') {
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
