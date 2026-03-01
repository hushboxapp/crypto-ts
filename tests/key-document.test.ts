import { describe, it, expect } from 'vitest';
import { Key, EncryptedKey, Document } from '../src';

describe('Key & Document Refactored Architecture', () => {
  it('should work end-to-end: Generate Key -> Lock with Password -> Encrypt Data', async () => {
    const data = new TextEncoder().encode('Highly sensitive data for the document.');
    const password = 'my-secure-password';

    // 1. Generate a new Key (master secret)
    const key = Key.generate();

    // 2. Encrypt it with a password (1-of-1)
    const encryptedKey = await key.encrypt([password], 1);
    const keyBlob = encryptedKey.encode();

    // 3. Encrypt data with the unlocked key
    const document = await Document.encrypt(data, key);
    const documentBlob = document.encode();

    // --- Recovery ---

    // 4. Import and decrypt the Key
    const importedEncryptedKey = EncryptedKey.decode(keyBlob);
    const recoveredKey = await importedEncryptedKey.decrypt([password]);
    expect(recoveredKey.material).toEqual(key.material);

    // 5. Decrypt the Document
    const importedDocument = Document.decode(documentBlob);
    const decryptedData = await importedDocument.decrypt(recoveredKey);

    expect(new TextDecoder().decode(decryptedData)).toBe('Highly sensitive data for the document.');
  });

  it('should support M-of-N passwords', async () => {
    const data = new TextEncoder().encode('M-of-N secret');
    const passwords = ['p1', 'p2', 'p3'];
    
    const key = Key.generate();
    
    // Encrypt with 2-of-3 threshold
    const encryptedKey = await key.encrypt(passwords, 2);
    const keyBlob = encryptedKey.encode();

    // Decrypt with 2 passwords
    const importedEK = EncryptedKey.decode(keyBlob);
    const recoveredKey = await importedEK.decrypt(['p1', 'p3']);
    
    const document = await Document.encrypt(data, recoveredKey);
    const decrypted = await document.decrypt(recoveredKey);
    expect(new TextDecoder().decode(decrypted)).toBe('M-of-N secret');

    // Fail with only 1 password
    await expect(importedEK.decrypt(['p2'])).rejects.toThrow(/Insufficient correct components/);
  });
});
