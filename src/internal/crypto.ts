import {
  NONCE_BYTES,
  boxKeypair,
  boxOpen,
  boxSeal,
  fromBase64Url,
  randomBytes,
  toBase64Url,
} from './nativeCrypto';

export interface SessionKeys {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface EncryptedFrame {
  v: 1;
  nonce: string;
  ciphertext: string;
}

export async function createSessionKeys(): Promise<SessionKeys> {
  await Promise.resolve();
  return boxKeypair();
}

export function exportPublicKey(key: Uint8Array): string {
  return toBase64Url(key);
}

export function importPublicKey(key: string): Uint8Array {
  return fromBase64Url(key);
}

export function encryptJson(
  value: unknown,
  remotePublicKey: Uint8Array,
  localPrivateKey: Uint8Array
): EncryptedFrame {
  const nonce = randomBytes(NONCE_BYTES);
  const ciphertext = boxSeal(
    JSON.stringify(value),
    nonce,
    remotePublicKey,
    localPrivateKey
  );
  return {
    v: 1,
    nonce: toBase64Url(nonce),
    ciphertext: toBase64Url(ciphertext),
  };
}

export function decryptJson<T>(
  frame: EncryptedFrame,
  remotePublicKey: Uint8Array,
  localPrivateKey: Uint8Array
): T {
  if (frame.v !== 1 || !frame.nonce || !frame.ciphertext) {
    throw new Error('Invalid encrypted frame');
  }
  const plaintext = boxOpen(
    fromBase64Url(frame.ciphertext),
    fromBase64Url(frame.nonce),
    remotePublicKey,
    localPrivateKey
  );
  return JSON.parse(plaintext) as T;
}

export function randomId(): string {
  return toBase64Url(randomBytes(12));
}
