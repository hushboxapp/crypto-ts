import { Key, Document, EncryptedKey } from '@hushboxapp/crypto';

// Encryption UI logic
document.getElementById('encryptBtn').onclick = async () => {
  const text = document.getElementById('plainText').value;
  const password = document.getElementById('encryptPassword').value;
  if (!password) return alert('Password is required');

  const masterKey = Key.generate();
  const encryptedKey = await masterKey.encrypt([password], 1);
  const data = new TextEncoder().encode(text);
  const doc = await Document.encrypt(data, masterKey);

  const resultEl = document.getElementById('encryptResult');
  resultEl.style.display = 'block';
  resultEl.innerHTML = `
    <strong>KEY:</strong><br>${encryptedKey.encode()}<br><br>
    <strong>DOC:</strong><br>${doc.encode()}
  `;
};

// Decryption UI logic
document.getElementById('decryptBtn').onclick = async () => {
  const keyStr = document.getElementById('cipherKey').value;
  const docStr = document.getElementById('cipherDoc').value;
  const password = document.getElementById('decryptPassword').value;
  if (!password) return alert('Password is required');

  try {
    const key = EncryptedKey.decode(keyStr.trim());
    const doc = Document.decode(docStr.trim());
    const unlockedKey = await key.decrypt([password]);
    const decryptedData = await doc.decrypt(unlockedKey);
    
    const resultEl = document.getElementById('decryptResult');
    resultEl.style.display = 'block';
    resultEl.textContent = 'Decrypted Text: ' + new TextDecoder().decode(decryptedData);
  } catch (e) {
    alert('Decryption failed: ' + e.message);
  }
};
