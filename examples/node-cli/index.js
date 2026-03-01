import { Command } from 'commander';
import { Key, Document, EncryptedKey } from '@vaultick/crypto';

const program = new Command();

program
  .name('vaultick-cli')
  .description('A simple CLI for encrypting and decrypting data using @vaultick/crypto')
  .version('1.0.0');

program.command('encrypt')
  .description('Encrypt a string with a password')
  .argument('<text>', 'Text to encrypt')
  .requiredOption('-p, --password <password>', 'Password to protect the key')
  .action(async (text, options) => {
    try {
      const masterKey = Key.generate();
      const encryptedKey = await masterKey.encrypt([options.password], 1);
      
      const data = new TextEncoder().encode(text);
      const encryptedDoc = await Document.encrypt(data, masterKey);
      
      console.log('
--- ENCRYPTED OUTPUT ---');
      console.log('KEY:', encryptedKey.encode());
      console.log('DOC:', encryptedDoc.encode());
      console.log('------------------------
');
    } catch (error) {
      console.error('Encryption failed:', error.message);
    }
  });

program.command('decrypt')
  .description('Decrypt data using an encrypted key and password')
  .requiredOption('-k, --key <key>', 'Serialized encrypted key')
  .requiredOption('-d, --doc <doc>', 'Serialized encrypted document')
  .requiredOption('-p, --password <password>', 'Password to unlock the key')
  .action(async (options) => {
    try {
      const restoredKey = EncryptedKey.decode(options.key);
      const restoredDoc = Document.decode(options.doc);
      
      const unlockedKey = await restoredKey.decrypt([options.password]);
      const decryptedData = await restoredDoc.decrypt(unlockedKey);
      
      console.log('
--- DECRYPTED TEXT ---');
      console.log(new TextDecoder().decode(decryptedData));
      console.log('----------------------
');
    } catch (error) {
      console.error('Decryption failed:', error.message);
    }
  });

program.parse();
