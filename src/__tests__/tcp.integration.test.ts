/** @jest-environment node */
import { afterEach, expect, it, jest } from '@jest/globals';
import { P2PTcpPeer } from '../P2PTcpPeer';
import { createSessionKeys, encryptJson } from '../internal/crypto';

// Only ICE/DTLS are simulated here. TCP sockets and encryption are real.
jest.mock('react-native-webrtc', () => {
  let id = 0;
  const registry = new Map();
  class Channel {
    readyState = 'connecting';
    other?: Channel;
    onopen?: () => void;
    onmessage?: (event: { data: string }) => void;
    send(data: string) {
      setImmediate(() => this.other?.onmessage?.({ data }));
    }
    close() {
      this.readyState = 'closed';
    }
  }
  class Peer {
    id = String(++id);
    localDescription: unknown;
    iceGatheringState = 'complete';
    channel?: Channel;
    host?: Peer;
    ondatachannel?: (event: { channel: Channel }) => void;
    constructor() {
      registry.set(this.id, this);
    }
    createDataChannel() {
      this.channel = new Channel();
      return this.channel;
    }
    async createOffer() {
      return { type: 'offer', sdp: this.id };
    }
    async createAnswer() {
      return { type: 'answer', sdp: this.id };
    }
    async setLocalDescription(value: unknown) {
      this.localDescription = value;
    }
    async setRemoteDescription(value: { type: string; sdp: string }) {
      if (value.type === 'offer') this.host = registry.get(value.sdp);
      else {
        const guest: Peer = registry.get(value.sdp);
        const channel = new Channel();
        guest.channel = channel;
        channel.other = this.channel;
        this.channel!.other = channel;
        guest.ondatachannel?.({ channel });
        setImmediate(() => {
          channel.readyState = 'open';
          this.channel!.readyState = 'open';
          channel.onopen?.();
          this.channel!.onopen?.();
        });
      }
    }
    close() {
      registry.delete(this.id);
    }
  }
  return {
    RTCPeerConnection: Peer,
    RTCSessionDescription: class {
      constructor(value: object) {
        Object.assign(this, value);
      }
    },
  };
});

const sessions: P2PTcpPeer[] = [];
afterEach(() => sessions.splice(0).forEach((peer) => peer.close()));

it('authenticates a real TCP stream and exchanges encrypted messages both ways', async () => {
  const host = new P2PTcpPeer();
  const guest = new P2PTcpPeer();
  sessions.push(host, guest);
  function connected(peer: P2PTcpPeer) {
    return new Promise<void>((resolve, reject) => {
      peer.on('state', (state) => {
        if (state === 'connected') resolve();
      });
      peer.on('error', reject);
    });
  }
  const connections = Promise.all([connected(host), connected(guest)]);
  const offer = await host.createOffer({
    advertiseHost: '127.0.0.1',
    listenHost: '127.0.0.1',
  });
  await host.acceptAnswer(await guest.acceptOffer(offer));
  await connections;
  const received = new Promise((resolve) => guest.on('message', resolve));
  host.sendMessage('TCP hello');
  expect(await received).toMatchObject({ payload: 'TCP hello' });
  const reply = new Promise((resolve) => host.on('message', resolve));
  guest.sendMessage({ reply: 'yes' });
  expect(await reply).toMatchObject({ payload: { reply: 'yes' } });
});

it('cancels before asynchronous key generation can open a listener', async () => {
  const peer = new P2PTcpPeer();
  sessions.push(peer);
  const pending = peer.createOffer({ advertiseHost: '127.0.0.1' });
  peer.close();
  await expect(pending).rejects.toThrow('cancelled');
  expect(peer.state).toBe('closed');
});

it('rejects reflected ciphertext instead of accepting its own ready frame', async () => {
  const peer = new P2PTcpPeer();
  sessions.push(peer);
  const hostKeys = await createSessionKeys();
  const guestKeys = await createSessionKeys();
  // Exercise the security boundary directly without needing an adversarial socket proxy.
  const internal = peer as unknown as {
    role: string;
    keys: typeof hostKeys;
    remotePublicKey: Uint8Array;
    handleEncryptedLine(line: string): void;
  };
  internal.role = 'host';
  internal.keys = hostKeys;
  internal.remotePublicKey = guestKeys.publicKey;
  const ownFrame = encryptJson(
    { v: 2, sender: 'host', seq: 1, kind: 'ready' },
    guestKeys.publicKey,
    hostKeys.privateKey
  );
  expect(() => internal.handleEncryptedLine(JSON.stringify(ownFrame))).toThrow(
    'invalid or replayed'
  );
});

it('prevents Wireshark packet sniffing from reading any plaintext, metadata, or decrypting with captured public keys', async () => {
  const net = require('node:net') as typeof import('node:net');
  const host = new P2PTcpPeer();
  const guest = new P2PTcpPeer();
  sessions.push(host, guest);

  const capturedWireChunks: string[] = [];
  let realHostPort = 0;

  // Start a real TCP MITM/Wireshark tap proxy that records every byte on the wire
  const snifferProxy = net.createServer((clientSocket) => {
    const targetSocket = net.createConnection(
      { host: '127.0.0.1', port: realHostPort },
      () => {
        clientSocket.on('data', (chunk) => {
          capturedWireChunks.push(chunk.toString('utf8'));
          targetSocket.write(chunk);
        });
        targetSocket.on('data', (chunk) => {
          capturedWireChunks.push(chunk.toString('utf8'));
          clientSocket.write(chunk);
        });
      }
    );
    clientSocket.on('close', () => targetSocket.destroy());
    targetSocket.on('close', () => clientSocket.destroy());
  });

  await new Promise<void>((resolve) =>
    snifferProxy.listen(0, '127.0.0.1', resolve)
  );
  const proxyPort = (snifferProxy.address() as { port: number }).port;

  try {
    function connected(peer: P2PTcpPeer) {
      return new Promise<void>((resolve, reject) => {
        peer.on('state', (state) => {
          if (state === 'connected') resolve();
        });
        peer.on('error', reject);
      });
    }

    const connections = Promise.all([connected(host), connected(guest)]);
    const offer = await host.createOffer({
      advertiseHost: '127.0.0.1',
      listenHost: '127.0.0.1',
    });
    // Route Guest's TCP connection through the Wireshark sniffer proxy
    const hostInternal = host as unknown as {
      endpoint: { host: string; port: number };
    };
    realHostPort = hostInternal.endpoint.port;
    hostInternal.endpoint = { host: '127.0.0.1', port: proxyPort };

    await host.acceptAnswer(await guest.acceptOffer(offer));
    await connections;

    const secretText = 'TOP_SECRET_WIRESHARK_TEST_994821';
    const received = new Promise((resolve) => guest.on('message', resolve));
    host.sendMessage({ secret: secretText, pin: 773412 });
    expect(await received).toMatchObject({
      payload: { secret: secretText, pin: 773412 },
    });

    const rawWireDump = capturedWireChunks.join('');
    expect(rawWireDump.length).toBeGreaterThan(0);

    // 1. Verify zero plaintext or metadata leaks in Wireshark TCP dump
    expect(rawWireDump).not.toContain(secretText);
    expect(rawWireDump).not.toContain(
      Buffer.from(secretText).toString('base64')
    );
    expect(rawWireDump).not.toContain(
      Buffer.from(secretText).toString('base64url')
    );
    expect(rawWireDump).not.toContain('773412');
    expect(rawWireDump).not.toContain('"ready"');
    expect(rawWireDump).not.toContain('"message"');
    expect(rawWireDump).not.toContain('"sender"');
    expect(rawWireDump).not.toContain('"sentAt"');

    // 2. Verify every line on the wire is an encrypted AEAD frame with unique nonces
    const lines = rawWireDump.trim().split('\n');
    expect(lines.length).toBeGreaterThanOrEqual(3);
    const nonces = new Set<string>();
    const attackerKeys = await createSessionKeys();
    const { decryptJson } = require('../internal/crypto');
    const hostPub = (host as unknown as { keys: { publicKey: Uint8Array } })
      .keys.publicKey;

    for (const line of lines) {
      const frame = JSON.parse(line) as {
        v: number;
        nonce: string;
        ciphertext: string;
      };
      expect(frame.v).toBe(1);
      expect(typeof frame.nonce).toBe('string');
      expect(typeof frame.ciphertext).toBe('string');
      nonces.add(frame.nonce);
      // 3. Verify an attacker with Wireshark cannot decrypt using captured public keys
      expect(() =>
        decryptJson(frame, hostPub, attackerKeys.privateKey)
      ).toThrow();
    }
    expect(nonces.size).toBe(lines.length);
  } finally {
    snifferProxy.close();
  }
});
