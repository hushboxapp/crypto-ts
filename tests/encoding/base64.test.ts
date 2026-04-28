import { describe, it, expect } from 'vitest';
import { Base64Engine } from '../../src/encoding/base64';

describe('Base64Engine', () => {
  const engine = new Base64Engine();

  it('should encode a string to base64', () => {
    const input = 'hello world';
    const output = engine.btoa(input);
    expect(output).toBe('aGVsbG8gd29ybGQ=');
  });

  it('should decode base64 to string', () => {
    const input = 'aGVsbG8gd29ybGQ=';
    const output = engine.atob(input);
    expect(output).toBe('hello world');
  });

  it('should handle special characters', () => {
    const input2 = 'Hello! @#%^&*()';
    const b64 = engine.btoa(input2);
    expect(engine.atob(b64)).toBe(input2);
  });

  it('should encode Uint8Array to base64', () => {
    const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const output = engine.encode(data);
    expect(output).toBe('SGVsbG8=');
  });

  it('should decode base64 to Uint8Array', () => {
    const input = 'SGVsbG8=';
    const output = engine.decode(input);
    expect(output).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
  });

  it('should round-trip binary data', () => {
    const data = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const b64 = engine.encode(data);
    const decoded = engine.decode(b64);
    expect(decoded).toEqual(data);
  });

  it('should round-trip empty Uint8Array', () => {
    const data = new Uint8Array(0);
    expect(engine.encode(data)).toBe('');
    expect(engine.decode('')).toEqual(data);
  });

  it('should throw InvalidEncodingError for non-base64 input', async () => {
    const { InvalidEncodingError } = await import('../../src/errors');
    // 0xa8 is outside the base64 alphabet; native atob throws DOMException.
    // We wrap it as InvalidEncodingError so callers see a library-domain error.
    const garbage = String.fromCharCode(0x3b, 0xa8);
    expect(() => engine.atob(garbage)).toThrow(InvalidEncodingError);
    expect(() => engine.decode(garbage)).toThrow(InvalidEncodingError);
  });

  it('should handle data larger than the encode chunk size', () => {
    // Exceeds the internal 0x8000-byte chunk window so the chunked encode path
    // is exercised. Uses a deterministic byte ramp to avoid pulling randomness
    // into the test.
    const size = 0x8000 * 3 + 17;
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) data[i] = i & 0xff;

    const b64 = engine.encode(data);
    const decoded = engine.decode(b64);
    expect(decoded.length).toBe(size);
    expect(decoded).toEqual(data);
  });
});
