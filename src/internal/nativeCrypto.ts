/* eslint-disable no-bitwise */
import { NativeModules } from 'react-native';

interface FprotNativeModuleSpec {
  randomBytes(size: number): string;
  sha256(utf8Input: string): string;
  boxKeypair(): string;
  boxSeal(
    plaintextUtf8: string,
    nonceB64: string,
    remotePubB64: string,
    localPrivB64: string
  ): string;
  boxOpen(
    ciphertextB64: string,
    nonceB64: string,
    remotePubB64: string,
    localPrivB64: string
  ): string;
  signKeypair(): string;
  signDetached(messageUtf8: string, secretKey64B64: string): string;
  verifyDetached(
    messageUtf8: string,
    signature64B64: string,
    publicKey32B64: string
  ): boolean;
  secretboxSeal(
    plaintextUtf8: string,
    nonceB64: string,
    key32B64: string
  ): string;
  secretboxOpen(
    ciphertextB64: string,
    nonceB64: string,
    key32B64: string
  ): string;
}

const ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) {
  LOOKUP[ALPHABET.charCodeAt(i)] = i;
}

export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  const len = bytes.length;
  while (i + 2 < len) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      ALPHABET[(n >> 18) & 63]! +
      ALPHABET[(n >> 12) & 63]! +
      ALPHABET[(n >> 6) & 63]! +
      ALPHABET[n & 63]!;
    i += 3;
  }
  const rem = len - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      ALPHABET[(n >> 18) & 63]! +
      ALPHABET[(n >> 12) & 63]! +
      ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

export function fromBase64Url(str: string): Uint8Array {
  if (typeof str !== 'string') {
    throw new Error('Invalid Base64URL string');
  }
  const len = str.length;
  if (len % 4 === 1) {
    throw new Error('Invalid Base64URL length');
  }
  const outLen = Math.floor((len * 3) / 4);
  const out = new Uint8Array(outLen);
  let outIdx = 0;
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < len; i++) {
    const code = str.charCodeAt(i);
    const val = code < 128 ? LOOKUP[code]! : -1;
    if (val === -1) {
      throw new Error('Invalid Base64URL character');
    }
    buffer = (buffer << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIdx++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

function getNativeModule(): FprotNativeModuleSpec | null {
  const mod = (NativeModules as { FprotNative?: FprotNativeModuleSpec })
    ?.FprotNative;
  if (mod && typeof mod.boxKeypair === 'function') {
    return mod;
  }
  return null;
}

function unwrapResult(res: string): string {
  if (typeof res === 'string' && res.startsWith('OK:')) {
    return res.slice(3);
  }
  const msg =
    typeof res === 'string' && res.startsWith('ERR:')
      ? res.slice(4)
      : 'Cryptographic operation failed';
  throw new Error(msg);
}

// Node.js fallback for unit/integration test environments
function getNodeCrypto(): typeof import('node:crypto') {
  const req = module.require.bind(module) as (
    id: string
  ) => typeof import('node:crypto');
  return req('node:crypto');
}

const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);
const X25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04,
  0x22, 0x04, 0x20,
]);

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export const NONCE_BYTES = 12;

export function randomBytes(size: number): Uint8Array {
  const native = getNativeModule();
  if (native) {
    return fromBase64Url(native.randomBytes(size));
  }
  const nc = getNodeCrypto();
  return new Uint8Array(nc.randomBytes(size));
}

export function sha256(utf8Input: string): Uint8Array {
  const native = getNativeModule();
  if (native) {
    return fromBase64Url(native.sha256(utf8Input));
  }
  const nc = getNodeCrypto();
  return new Uint8Array(
    nc.createHash('sha256').update(utf8Input, 'utf8').digest()
  );
}

export function boxKeypair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const native = getNativeModule();
  if (native) {
    const [pubB64, privB64] = native.boxKeypair().split('.');
    return {
      publicKey: fromBase64Url(pubB64!),
      privateKey: fromBase64Url(privB64!),
    };
  }
  const nc = getNodeCrypto();
  const { publicKey, privateKey } = nc.generateKeyPairSync('x25519');
  const pubDer = publicKey.export({ type: 'spki', format: 'der' });
  const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
  return {
    publicKey: new Uint8Array(pubDer.subarray(pubDer.length - 32)),
    privateKey: new Uint8Array(privDer.subarray(privDer.length - 32)),
  };
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

function nodeDeriveBoxKey(
  remotePub32: Uint8Array,
  localPriv32: Uint8Array
): Uint8Array {
  const nc = getNodeCrypto();
  const pubKey = nc.createPublicKey({
    key: Buffer.from(concatBytes(X25519_SPKI_PREFIX, remotePub32)),
    format: 'der',
    type: 'spki',
  });
  const privKey = nc.createPrivateKey({
    key: Buffer.from(concatBytes(X25519_PKCS8_PREFIX, localPriv32)),
    format: 'der',
    type: 'pkcs8',
  });
  const localPubDer = nc
    .createPublicKey(privKey)
    .export({ type: 'spki', format: 'der' });
  const localPub32 = new Uint8Array(
    localPubDer.subarray(localPubDer.length - 32)
  );
  if (compareBytes(localPub32, remotePub32) === 0) {
    throw new Error('Peer public key matches local key');
  }
  const shared = nc.diffieHellman({ privateKey: privKey, publicKey: pubKey });
  if (shared.every((b) => b === 0)) {
    throw new Error('Invalid low-order X25519 public key');
  }
  const [firstPub, secondPub] =
    compareBytes(localPub32, remotePub32) < 0
      ? [localPub32, remotePub32]
      : [remotePub32, localPub32];
  return new Uint8Array(
    nc
      .createHash('sha256')
      .update('fprot.box.v1', 'utf8')
      .update(shared)
      .update(firstPub)
      .update(secondPub)
      .digest()
  );
}

export function boxSeal(
  plaintextUtf8: string,
  nonce12: Uint8Array,
  remotePub32: Uint8Array,
  localPriv32: Uint8Array
): Uint8Array {
  const native = getNativeModule();
  if (native) {
    const res = native.boxSeal(
      plaintextUtf8,
      toBase64Url(nonce12),
      toBase64Url(remotePub32),
      toBase64Url(localPriv32)
    );
    return fromBase64Url(unwrapResult(res));
  }
  const key = nodeDeriveBoxKey(remotePub32, localPriv32);
  return secretboxSeal(plaintextUtf8, nonce12, key);
}

export function boxOpen(
  ciphertextWithTag: Uint8Array,
  nonce12: Uint8Array,
  remotePub32: Uint8Array,
  localPriv32: Uint8Array
): string {
  const native = getNativeModule();
  if (native) {
    const res = native.boxOpen(
      toBase64Url(ciphertextWithTag),
      toBase64Url(nonce12),
      toBase64Url(remotePub32),
      toBase64Url(localPriv32)
    );
    return unwrapResult(res);
  }
  const key = nodeDeriveBoxKey(remotePub32, localPriv32);
  return secretboxOpen(ciphertextWithTag, nonce12, key);
}

export function signKeypair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const native = getNativeModule();
  if (native) {
    const [pubB64, priv64B64] = native.signKeypair().split('.');
    return {
      publicKey: fromBase64Url(pubB64!),
      privateKey: fromBase64Url(priv64B64!),
    };
  }
  const nc = getNodeCrypto();
  const { publicKey, privateKey } = nc.generateKeyPairSync('ed25519');
  const pubDer = publicKey.export({ type: 'spki', format: 'der' });
  const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
  const pub32 = new Uint8Array(pubDer.subarray(pubDer.length - 32));
  const seed32 = new Uint8Array(privDer.subarray(privDer.length - 32));
  return {
    publicKey: pub32,
    privateKey: concatBytes(seed32, pub32),
  };
}

export function signDetached(
  messageUtf8: string,
  secretKey64: Uint8Array
): Uint8Array {
  if (secretKey64.length !== 64) {
    throw new Error('Invalid Ed25519 secret key');
  }
  const native = getNativeModule();
  if (native) {
    const res = native.signDetached(messageUtf8, toBase64Url(secretKey64));
    return fromBase64Url(unwrapResult(res));
  }
  const nc = getNodeCrypto();
  const seed32 = secretKey64.subarray(0, 32);
  const privKey = nc.createPrivateKey({
    key: Buffer.from(concatBytes(ED25519_PKCS8_PREFIX, seed32)),
    format: 'der',
    type: 'pkcs8',
  });
  const sig = nc.sign(null, Buffer.from(messageUtf8, 'utf8'), privKey);
  return new Uint8Array(sig);
}

export function verifyDetached(
  messageUtf8: string,
  signature64: Uint8Array,
  publicKey32: Uint8Array
): boolean {
  if (signature64.length !== 64 || publicKey32.length !== 32) {
    return false;
  }
  const native = getNativeModule();
  if (native) {
    return Boolean(
      native.verifyDetached(
        messageUtf8,
        toBase64Url(signature64),
        toBase64Url(publicKey32)
      )
    );
  }
  try {
    const nc = getNodeCrypto();
    const pubKey = nc.createPublicKey({
      key: Buffer.from(concatBytes(ED25519_SPKI_PREFIX, publicKey32)),
      format: 'der',
      type: 'spki',
    });
    return nc.verify(
      null,
      Buffer.from(messageUtf8, 'utf8'),
      pubKey,
      Buffer.from(signature64)
    );
  } catch {
    return false;
  }
}

export function secretboxKeygen(): Uint8Array {
  return randomBytes(32);
}

export function secretboxSeal(
  plaintextUtf8: string,
  nonce12: Uint8Array,
  key32: Uint8Array
): Uint8Array {
  const native = getNativeModule();
  if (native) {
    const res = native.secretboxSeal(
      plaintextUtf8,
      toBase64Url(nonce12),
      toBase64Url(key32)
    );
    return fromBase64Url(unwrapResult(res));
  }
  const nc = getNodeCrypto();
  const cipher = nc.createCipheriv('aes-256-gcm', key32, nonce12);
  const encrypted = Buffer.concat([
    cipher.update(plaintextUtf8, 'utf8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return new Uint8Array(encrypted);
}

export function secretboxOpen(
  ciphertextWithTag: Uint8Array,
  nonce12: Uint8Array,
  key32: Uint8Array
): string {
  const native = getNativeModule();
  if (native) {
    const res = native.secretboxOpen(
      toBase64Url(ciphertextWithTag),
      toBase64Url(nonce12),
      toBase64Url(key32)
    );
    return unwrapResult(res);
  }
  if (ciphertextWithTag.length < 16) {
    throw new Error('Ciphertext too short');
  }
  const nc = getNodeCrypto();
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const body = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const decipher = nc.createDecipheriv('aes-256-gcm', key32, nonce12);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(body), decipher.final()]);
  return plain.toString('utf8');
}
