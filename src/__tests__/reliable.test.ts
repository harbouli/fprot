import {
  beforeAll,
  beforeEach,
  afterEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { EventBus } from '../internal/EventBus';
import { ReliableConversation } from '../reliable/ReliableConversation';
import {
  createEncryptedStorage,
  loadOrCreateIdentity,
} from '../reliable/identity';
import { MessageStore } from '../reliable/MessageStore';
import {
  decodeSignal,
  encodeSignal,
  type Signal,
} from '../reliable/SignalProtocol';
import type {
  KeyValueStorage,
  PeerIdentity,
  SignalTransport,
  SessionTransport,
} from '../reliable/types';
import type { JsonValue, PeerEventMap } from '../types';

jest.mock('../P2PTcpPeer', () => ({ P2PTcpPeer: jest.fn() }));

class MemoryStorage implements KeyValueStorage {
  values = new Map<string, string>();
  fail = false;
  async getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  async setItem(key: string, value: string) {
    if (this.fail) throw new Error('disk full');
    this.values.set(key, value);
  }
}

class Signals implements SignalTransport {
  handlers?: Parameters<SignalTransport['start']>[0];
  other?: Signals;
  sent: string[] = [];
  available = true;
  start(handlers: Parameters<SignalTransport['start']>[0]) {
    this.handlers = handlers;
    handlers.onOnline(this.available);
  }
  stop() {
    this.handlers = undefined;
  }
  send(raw: string) {
    this.sent.push(raw);
    if (!this.available) return false;
    void Promise.resolve().then(() => this.other?.handlers?.onMessage(raw));
    return true;
  }
}

let counter = 0;
const offers = new Map<string, FakePeer>();
const peers: FakePeer[] = [];
let dropAcks = false;
class FakePeer implements SessionTransport {
  events = new EventBus<PeerEventMap>();
  other?: FakePeer;
  closed = false;
  sent: JsonValue[] = [];
  constructor() {
    peers.push(this);
  }
  on: SessionTransport['on'] = (event, callback) =>
    this.events.on(event, callback);
  async createOffer() {
    const offer = `offer-${++counter}`;
    offers.set(offer, this);
    return offer;
  }
  async acceptOffer(offer: string) {
    this.other = offers.get(offer)!;
    this.other.other = this;
    return 'answer';
  }
  async acceptAnswer() {
    this.events.emit('state', 'connected');
    this.other!.events.emit('state', 'connected');
  }
  sendMessage(value: JsonValue) {
    if (this.closed) throw new Error('closed');
    this.sent.push(value);
    const kind = (value as { kind?: string }).kind;
    if (!(kind === 'ack' && dropAcks))
      void Promise.resolve().then(() => {
        if (!this.closed && !this.other?.closed)
          this.other?.events.emit('message', {
            id: 'transport',
            payload: value,
            sentAt: Date.now(),
          });
      });
    return 'transport';
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.events.emit('close', undefined);
    this.other?.events.emit('close', undefined);
  }
}

let a: PeerIdentity;
let b: PeerIdentity;
const chats: ReliableConversation[] = [];
beforeAll(async () => {
  a = await loadOrCreateIdentity(new MemoryStorage());
  b = await loadOrCreateIdentity(new MemoryStorage());
});
beforeEach(() => {
  jest.useFakeTimers();
  dropAcks = false;
  peers.length = 0;
  offers.clear();
});
afterEach(() => {
  chats.splice(0).forEach((chat) => chat.stop());
  jest.useRealTimers();
});
async function settle() {
  for (let i = 0; i < 80; ++i) await Promise.resolve();
}
function pair(stores = [new MemoryStorage(), new MemoryStorage()] as const) {
  const sa = new Signals();
  const sb = new Signals();
  sa.other = sb;
  sb.other = sa;
  const common = {
    conversationId: 'chat',
    createPeer: () => new FakePeer(),
    retryMinMs: 100,
    retryMaxMs: 500,
    handshakeTimeoutMs: 1000,
    heartbeatMs: 100,
    idleTimeoutMs: 350,
    ackTimeoutMs: 200,
  };
  const host = new ReliableConversation({
    ...common,
    role: 'host',
    getHostOptions: () => ({ advertiseHost: '10.0.0.1' }),
    identity: a,
    remotePublicKey: b.publicKey,
    storage: stores[0],
    signaling: sa,
  });
  const guest = new ReliableConversation({
    ...common,
    role: 'guest',
    identity: b,
    remotePublicKey: a.publicKey,
    storage: stores[1],
    signaling: sb,
  });
  chats.push(host, guest);
  return { host, guest, sa, sb, stores };
}
async function connect(pairing: ReturnType<typeof pair>) {
  await pairing.host.start();
  await pairing.guest.start();
  await settle();
  expect(pairing.host.state).toBe('connected');
  expect(pairing.guest.state).toBe('connected');
}

describe('durable delivery and recovery', () => {
  it('persists and delivers queued messages after the guest returns', async () => {
    const p = pair();
    await connect(p);
    p.guest.setAvailable(false);
    const id = await p.host.sendMessage('offline hello');
    expect(p.host.messages[0]?.status).toBe('pending');
    expect(p.guest.messages).toHaveLength(0);
    p.guest.setAvailable(true);
    await settle();
    expect(p.guest.messages[0]?.id).toBe(id);
    expect(p.host.messages[0]?.status).toBe('delivered');
  });

  it('retries a lost acknowledgement after restart without duplicate display', async () => {
    const p = pair();
    await connect(p);
    dropAcks = true;
    const id = await p.host.sendMessage('only once');
    await settle();
    expect(p.guest.messages).toHaveLength(1);
    expect(p.host.messages[0]?.status).toBe('pending');
    p.host.stop();
    p.guest.stop();
    dropAcks = false;
    const restarted = pair(p.stores);
    await connect(restarted);
    await settle();
    expect(restarted.guest.messages).toHaveLength(1);
    expect(restarted.host.messages[0]).toMatchObject({
      id,
      status: 'delivered',
    });
  });

  it('never acknowledges a message when the receiver cannot commit it', async () => {
    const p = pair();
    await connect(p);
    p.stores[1].fail = true;
    await p.host.sendMessage('keep pending');
    await settle();
    expect(p.guest.messages).toHaveLength(0);
    expect(p.host.messages[0]?.status).toBe('pending');
    expect(
      peers
        .flatMap((peer) => peer.sent)
        .some((value) => (value as { kind: string }).kind === 'ack')
    ).toBe(false);
  });

  it('does not transmit or display an outgoing message when persistence fails', async () => {
    const p = pair();
    await connect(p);
    p.stores[0].fail = true;
    await expect(p.host.sendMessage('unsaved')).rejects.toThrow('disk full');
    await settle();
    expect(p.host.messages).toHaveLength(0);
    expect(p.guest.messages).toHaveLength(0);
  });

  it('uses ACK timeouts to reconnect and replay outstanding messages', async () => {
    const p = pair();
    await connect(p);
    dropAcks = true;
    await p.host.sendMessage('retry me');
    await settle();
    dropAcks = false;
    await jest.advanceTimersByTimeAsync(1500);
    await settle();
    expect(p.host.messages[0]?.status).toBe('delivered');
    expect(p.guest.messages).toHaveLength(1);
  });

  it('detects half-open peers using heartbeat deadlines', async () => {
    const p = pair();
    await connect(p);
    const oldPeers = [...peers];
    oldPeers.forEach((peer) => {
      peer.other = undefined;
    });
    await jest.advanceTimersByTimeAsync(1500);
    await settle();
    expect(oldPeers.every((peer) => peer.closed)).toBe(true);
    expect(p.host.state).toBe('connected');
  });

  it('keeps the TCP chat working if signaling disconnects', async () => {
    const p = pair();
    await connect(p);
    p.sa.available = false;
    p.sb.available = false;
    p.sa.handlers?.onOnline(false);
    p.sb.handlers?.onOnline(false);
    await p.host.sendMessage('still direct');
    await settle();
    expect(p.host.messages[0]?.status).toBe('delivered');
  });

  it('ignores stale offers after a new reconnect challenge', async () => {
    const p = pair();
    await connect(p);
    const oldOffer = p.sa.sent.find(
      (raw) => JSON.parse(JSON.parse(raw).body).type === 'offer'
    )!;
    p.guest.setAvailable(false);
    p.sa.available = false;
    p.guest.setAvailable(true);
    await settle();
    const count = peers.length;
    p.sb.handlers?.onMessage(oldOffer);
    await settle();
    expect(peers).toHaveLength(count);
    expect(p.guest.state).not.toBe('connected');
  });

  it('stops timers and does not reopen after stop', async () => {
    const p = pair();
    await connect(p);
    p.host.stop();
    p.guest.stop();
    const count = peers.length;
    await jest.advanceTimersByTimeAsync(60_000);
    expect(peers).toHaveLength(count);
    expect(jest.getTimerCount()).toBe(0);
  });
});

describe('storage and identity', () => {
  it('serializes concurrent writes and restores history', async () => {
    const storage = new MemoryStorage();
    const store = new MessageStore(storage, 'chat');
    await store.load();
    await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        store.add({
          id: String(i).padStart(16, '0'),
          payload: i,
          sentAt: i,
          direction: 'outgoing',
          status: 'pending',
        })
      )
    );
    const restored = new MessageStore(storage, 'chat');
    await restored.load();
    expect(restored.snapshot()).toHaveLength(10);
  });

  it('fails closed on corrupt history', async () => {
    const storage = new MemoryStorage();
    await storage.setItem('chat', '{bad');
    await expect(new MessageStore(storage, 'chat').load()).rejects.toThrow();
  });

  it('stores identity once and encrypts history across restarts', async () => {
    const raw = new MemoryStorage();
    const secure = new MemoryStorage();
    const identity = await loadOrCreateIdentity(secure);
    expect(await loadOrCreateIdentity(secure)).toEqual(identity);
    const storage = await createEncryptedStorage(raw, secure);
    await storage.setItem('chat', 'secret message');
    expect(raw.values.get('chat')).not.toContain('secret message');
    const restored = await createEncryptedStorage(raw, secure);
    expect(await restored.getItem('chat')).toBe('secret message');
    raw.values.set('another-chat', raw.values.get('chat')!);
    await expect(restored.getItem('another-chat')).rejects.toThrow('binding');
  });

  it('rejects forged signatures and another conversation', () => {
    const signal: Signal = {
      v: 1,
      from: a.publicKey,
      to: b.publicKey,
      conversationId: 'chat',
      type: 'request',
      challenge: '1234567890123456',
      attempt: '',
      sdp: '',
    };
    const raw = encodeSignal(signal, a);
    expect(decodeSignal(raw, b.publicKey, a.publicKey, 'chat')).toEqual(signal);
    expect(() =>
      decodeSignal(raw, b.publicKey, a.publicKey, 'different')
    ).toThrow('scope');
    expect(() =>
      decodeSignal(encodeSignal(signal, b), b.publicKey, a.publicKey, 'chat')
    ).toThrow('signature');
    const envelope = JSON.parse(raw);
    envelope.body = envelope.body.replace('chat', 'evil');
    expect(() =>
      decodeSignal(JSON.stringify(envelope), b.publicKey, a.publicKey, 'chat')
    ).toThrow('signature');
  });
});
