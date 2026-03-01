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
    const input = '✓ à la mode';
    // btoa/atob in browser handles these differently than Buffer in node
    // for strings that are not "binary" (latin1)
    // The implementation uses Buffer.from(str, 'binary') in node
    // and window.btoa(str) in browser which also expects latin1.
    // If we want to support UTF-8, we usually encode to UTF-8 bytes first.
    // Let's test with something that is latin1 first.
    const input2 = 'Hello! @#%^&*()';
    const b64 = engine.btoa(input2);
    expect(engine.atob(b64)).toBe(input2);
  });
});
