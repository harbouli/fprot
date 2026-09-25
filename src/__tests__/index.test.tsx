import { describe, expect, it } from '@jest/globals';
import { NativeModules } from 'react-native';

import { LineDecoder } from '../internal/LineDecoder';
import {
  boxKeypair,
  boxOpen,
  boxSeal,
  fromBase64Url,
  randomBytes,
  secretboxOpen,
  secretboxSeal,
  sha256,
  signDetached,
  signKeypair,
  toBase64Url,
  verifyDetached,
} from '../internal/nativeCrypto';
import { decodeSignal, encodeSignal } from '../internal/signaling';
import { TcpSocket } from '../internal/tcp';

describe('signaling codec', () => {
  it('round-trips an SDP offer', () => {
    const encoded = encodeSignal('offer', 'v=0\r\nexample');
    expect(decodeSignal(encoded, 'offer')).toEqual({
      v: 1,
      type: 'offer',
      sdp: 'v=0\r\nexample',
    });
  });

  it('rejects a signal of the wrong type', () => {
    expect(() => decodeSignal(encodeSignal('answer', 'sdp'), 'offer')).toThrow(
      'Expected a version 1 WebRTC offer'
    );
  });
});

describe('TCP line decoder', () => {
  it('reassembles fragmented and coalesced frames', () => {
    const decoder = new LineDecoder(100);
    expect(decoder.push('{"a":')).toEqual([]);
    expect(decoder.push('1}\n{"b":2}\n')).toEqual(['{"a":1}', '{"b":2}']);
  });

  it('rejects an oversized incomplete frame', () => {
    const decoder = new LineDecoder(3);
    expect(() => decoder.push('1234')).toThrow('exceeds');
  });

  it('allows multiple valid frames in one large TCP chunk', () => {
    const decoder = new LineDecoder(3);
    expect(decoder.push('123\n456\n')).toEqual(['123', '456']);
  });
});

describe('native crypto & base64url', () => {
  it('round-trips arbitrary byte lengths through Base64URL', () => {
    for (const len of [0, 1, 2, 3, 12, 16, 31, 32, 33, 64]) {
      const buf = randomBytes(len);
      const encoded = toBase64Url(buf);
      expect(fromBase64Url(encoded)).toEqual(buf);
    }
    expect(() => fromBase64Url('abc=')).toThrow('Invalid Base64URL');
    expect(() => fromBase64Url('a')).toThrow('Invalid Base64URL');
  });

  it('delegates crypto and TCP operations to NativeModules.FprotNative when present', async () => {
    const alice = boxKeypair();
    const bob = boxKeypair();
    const sigKeys = signKeypair();
    const nonce = randomBytes(12);
    const cipher = boxSeal(
      'hello native',
      nonce,
      bob.publicKey,
      alice.privateKey
    );
    const sig = signDetached('msg', sigKeys.privateKey);
    const secretKey = randomBytes(32);
    const sbCipher = secretboxSeal('secret', nonce, secretKey);

    const holder = NativeModules as Record<string, unknown>;
    holder.FprotNative = {
      randomBytes: () => toBase64Url(nonce),
      sha256: () => toBase64Url(new Uint8Array(32).fill(7)),
      boxKeypair: () =>
        `${toBase64Url(alice.publicKey)}.${toBase64Url(alice.privateKey)}`,
      boxSeal: () => `OK:${toBase64Url(cipher)}`,
      boxOpen: (c: string) =>
        c === 'YmFk' ? 'ERR:Tampered frame' : 'OK:hello native',
      signKeypair: () =>
        `${toBase64Url(sigKeys.publicKey)}.${toBase64Url(sigKeys.privateKey)}`,
      signDetached: () => `OK:${toBase64Url(sig)}`,
      verifyDetached: () => true,
      secretboxSeal: () => `OK:${toBase64Url(sbCipher)}`,
      secretboxOpen: () => 'OK:secret',
      tcpServerListen: async () => 43210,
      tcpServerClose: async () => undefined,
      tcpConnect: async () => undefined,
      tcpWrite: async () => undefined,
      tcpDestroy: async () => undefined,
      addListener: () => undefined,
      removeListeners: () => undefined,
    };

    try {
      expect(randomBytes(12)).toEqual(nonce);
      expect(sha256('test')).toEqual(new Uint8Array(32).fill(7));
      expect(boxKeypair()).toEqual(alice);
      expect(
        boxSeal('hello native', nonce, bob.publicKey, alice.privateKey)
      ).toEqual(cipher);
      expect(boxOpen(cipher, nonce, alice.publicKey, bob.privateKey)).toBe(
        'hello native'
      );
      expect(() =>
        boxOpen(fromBase64Url('YmFk'), nonce, alice.publicKey, bob.privateKey)
      ).toThrow('Tampered frame');
      expect(signKeypair()).toEqual(sigKeys);
      expect(signDetached('msg', sigKeys.privateKey)).toEqual(sig);
      expect(verifyDetached('msg', sig, sigKeys.publicKey)).toBe(true);
      expect(secretboxSeal('secret', nonce, secretKey)).toEqual(sbCipher);
      expect(secretboxOpen(sbCipher, nonce, secretKey)).toBe('secret');

      const server = TcpSocket.createServer(() => {});
      await new Promise<void>((resolve) => {
        server.listen({ port: 0, host: '127.0.0.1' }, () => resolve());
      });
      expect(server.address()?.port).toBe(43210);
      server.close();

      const client = TcpSocket.createConnection({
        host: '127.0.0.1',
        port: 43210,
      });
      await new Promise<void>((resolve, reject) => {
        client.write('ping\n', 'utf8', (err) =>
          err ? reject(err) : resolve()
        );
      });
      client.destroy();
    } finally {
      delete holder.FprotNative;
    }
  });
});
