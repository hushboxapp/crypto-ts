import {
  AESGCMProvider,
  Argon2WorkerProvider,
  EncodingFactory,
  EncryptionFactory,
  HashingFactory,
  RandomnessFactory,
  SharingFactory,
  type EncodingProvider,
  type EncryptionProvider,
  type HashingProvider,
  type RandomnessProvider,
  type SharingProvider,
} from '@hushboxapp/crypto';

const encoding: EncodingProvider = EncodingFactory.getProvider('base64');
const encryption: EncryptionProvider = EncryptionFactory.getProvider('aes-gcm');
const hashing: HashingProvider = HashingFactory.getProvider('argon2id');
const randomness: RandomnessProvider = RandomnessFactory.getProvider('native');
const sharing: SharingProvider = SharingFactory.getProvider('shamir');
const cipher = new AESGCMProvider();
const encrypted: Promise<Uint8Array> = cipher.encrypt(
  encoding.decode('AA=='),
  randomness.generate(32),
  randomness.generate(12),
);
const worker = new Argon2WorkerProvider(() => new Worker('worker.js'));
const terminated: void = worker.terminate();

// A declaration regression to `any` must not silently pass this consumer check.
// @ts-expect-error encryption keys must be byte arrays
cipher.encrypt(new Uint8Array(), 'invalid-key', new Uint8Array(12));
// @ts-expect-error factory results retain their provider interfaces
const invalidProvider: string = EncryptionFactory.getProvider('aes-gcm');

void [encryption, hashing, sharing, encrypted, terminated, invalidProvider];
