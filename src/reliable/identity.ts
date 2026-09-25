import {
  exportPublicKey as encode,
  importPublicKey as decode,
} from '../internal/crypto';
import {
  NONCE_BYTES,
  randomBytes,
  secretboxKeygen,
  secretboxOpen,
  secretboxSeal,
  sha256,
  signDetached,
  signKeypair,
  verifyDetached,
} from '../internal/nativeCrypto';
import type { KeyValueStorage, PeerIdentity } from './types';

export async function loadOrCreateIdentity(
  secureStorage: KeyValueStorage
): Promise<PeerIdentity> {
  const saved = await secureStorage.getItem('fprot.identity.v1');
  if (saved !== null) {
    const identity: PeerIdentity = JSON.parse(saved);
    validateIdentity(identity);
    return identity;
  }
  const keys = signKeypair();
  const identity = {
    publicKey: encode(keys.publicKey),
    privateKey: encode(keys.privateKey),
  };
  await secureStorage.setItem('fprot.identity.v1', JSON.stringify(identity));
  return identity;
}

export function validatePublicKey(key: string): void {
  if (
    typeof key !== 'string' ||
    decode(key).length !== 32 ||
    encode(decode(key)) !== key
  ) {
    throw new Error('Invalid Ed25519 peer public key');
  }
}

export function validateIdentity(identity: PeerIdentity): void {
  validatePublicKey(identity.publicKey);
  if (
    decode(identity.privateKey).length !== 64 ||
    !verify(
      'fprot.identity.check',
      sign('fprot.identity.check', identity),
      identity.publicKey
    )
  ) {
    throw new Error(
      'Stored identity is invalid; do not silently replace a paired identity'
    );
  }
}

export function sign(body: string, identity: PeerIdentity): string {
  return encode(signDetached(body, decode(identity.privateKey)));
}

export function verify(
  body: string,
  signature: string,
  publicKey: string
): boolean {
  try {
    return verifyDetached(body, decode(signature), decode(publicKey));
  } catch {
    return false;
  }
}

export function conversationStorageKey(
  id: string,
  local: string,
  remote: string
): string {
  return `fprot.chat.${encode(sha256(JSON.stringify([id, local, remote])))}`;
}

/** Encrypt local chat snapshots; keep the random storage key in secureStorage. */
export async function createEncryptedStorage(
  storage: KeyValueStorage,
  secureStorage: KeyValueStorage
): Promise<KeyValueStorage> {
  const keyName = 'fprot.storage-key.v1';
  let encoded = await secureStorage.getItem(keyName);
  if (encoded === null) {
    encoded = encode(secretboxKeygen());
    await secureStorage.setItem(keyName, encoded);
  }
  const key = decode(encoded);
  if (key.length !== 32) throw new Error('Invalid local storage key');
  return {
    async getItem(name) {
      const saved = await storage.getItem(name);
      if (saved === null) return null;
      const envelope = JSON.parse(saved);
      if (envelope.v !== 1)
        throw new Error('Unsupported encrypted storage version');
      const plain = JSON.parse(
        secretboxOpen(decode(envelope.ciphertext), decode(envelope.nonce), key)
      );
      if (plain.name !== name || typeof plain.value !== 'string')
        throw new Error('Stored record binding mismatch');
      return plain.value;
    },
    async setItem(name, value) {
      const nonce = randomBytes(NONCE_BYTES);
      const ciphertext = secretboxSeal(
        JSON.stringify({ name, value }),
        nonce,
        key
      );
      await storage.setItem(
        name,
        JSON.stringify({
          v: 1,
          nonce: encode(nonce),
          ciphertext: encode(ciphertext),
        })
      );
    },
  };
}
