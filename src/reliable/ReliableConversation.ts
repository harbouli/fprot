import { P2PTcpPeer } from '../P2PTcpPeer';
import { EventBus } from '../internal/EventBus';
import { randomId } from '../internal/crypto';
import type { JsonValue, Unsubscribe } from '../types';
import {
  conversationStorageKey,
  validateIdentity,
  validatePublicKey,
} from './identity';
import { MessageStore, validatePayload } from './MessageStore';
import { decodeSignal, encodeSignal, type Signal } from './SignalProtocol';
import type {
  ChatMessage,
  ConversationEvents,
  ConversationState,
  ReliableConversationOptions,
  SessionTransport,
} from './types';

/** Persistent conversation; a fresh disposable TCP peer is created for each attempt. */
export class ReliableConversation {
  private events = new EventBus<ConversationEvents>();
  private store?: MessageStore;
  private peer?: SessionTransport;
  private unsubs: Unsubscribe[] = [];
  private active = false;
  private online = false;
  private signalOnline = false;
  private _state: ConversationState = 'stopped';
  private generation = 0;
  private challenge = '';
  private attempt = '';
  private answered = false;
  private retries = 0;
  private retryTimer?: ReturnType<typeof setTimeout>;
  private deadline?: ReturnType<typeof setTimeout>;
  private heartbeat?: ReturnType<typeof setInterval>;
  private ackTimer?: ReturnType<typeof setTimeout>;
  private inFlight?: string;
  private lastReceived = 0;
  private inbound: Promise<void> = Promise.resolve();
  private starting?: Promise<void>;
  private readonly timing;

  constructor(private options: ReliableConversationOptions) {
    this.timing = {
      min: options.retryMinMs ?? 1000,
      max: options.retryMaxMs ?? 30_000,
      handshake: options.handshakeTimeoutMs ?? 45_000,
      heartbeat: options.heartbeatMs ?? 10_000,
      idle: options.idleTimeoutMs ?? 35_000,
      ack: options.ackTimeoutMs ?? 10_000,
    };
    if (
      Object.values(this.timing).some(
        (value) => !Number.isFinite(value) || value <= 0
      ) ||
      this.timing.max < this.timing.min ||
      this.timing.idle <= this.timing.heartbeat
    )
      throw new Error('Invalid reconnect/heartbeat timing');
    if (!options.conversationId || options.conversationId.length > 128)
      throw new Error('Conversation ID must contain 1–128 characters');
    if (options.role === 'host' && !options.getHostOptions)
      throw new Error('Host requires getHostOptions');
    if ((options.peerOptions?.maxFrameBytes ?? 1024 * 1024) < 32 * 1024)
      throw new Error('Reliable conversations require maxFrameBytes >= 32768');
  }

  get state(): ConversationState {
    return this._state;
  }
  get messages(): ChatMessage[] {
    return this.store?.snapshot() ?? [];
  }
  on<K extends keyof ConversationEvents>(
    event: K,
    callback: (value: ConversationEvents[K]) => void
  ): Unsubscribe {
    return this.events.on(event, callback);
  }

  start(): Promise<void> {
    if (this.starting) return this.starting;
    if (this.active) return Promise.resolve();
    this.active = true;
    this.starting = this.initialize()
      .catch((error) => {
        this.stop();
        throw error;
      })
      .finally(() => {
        this.starting = undefined;
      });
    return this.starting;
  }

  private async initialize(): Promise<void> {
    validateIdentity(this.options.identity);
    validatePublicKey(this.options.remotePublicKey);
    if (this.options.identity.publicKey === this.options.remotePublicKey)
      throw new Error('Cannot pair with yourself');
    if (!this.store) {
      const store = new MessageStore(
        this.options.storage,
        conversationStorageKey(
          this.options.conversationId,
          this.options.identity.publicKey,
          this.options.remotePublicKey
        )
      );
      await store.load();
      this.store = store;
    }
    if (!this.active) return;
    this.publishMessages();
    this.online = true;
    this.setState('reconnecting');
    this.options.signaling.start({
      onOnline: (online) => {
        if (!this.active) return;
        this.signalOnline = online;
        if (online && this.online && this.state !== 'connected' && !this.peer)
          this.discover();
      },
      onMessage: (raw) => {
        if (!this.active || !this.online) return;
        void this.receiveSignal(raw).catch((error) => this.report(error));
      },
    });
    this.scheduleRetry();
  }

  /** Resolves after the message is durable locally; delivery is reported via messages. */
  async sendMessage(payload: JsonValue): Promise<string> {
    if (!this.store) throw new Error('Call and await start() before sending');
    validatePayload(payload);
    const message: ChatMessage = {
      id: randomId(),
      payload,
      sentAt: Date.now(),
      direction: 'outgoing',
      status: 'pending',
    };
    await this.store.add(message);
    this.publishMessages();
    this.flush();
    return message.id;
  }

  /** Feed foreground/background and connectivity changes here. Pending messages survive. */
  setAvailable(available: boolean): void {
    if (!this.active || this.online === available) return;
    this.online = available;
    this.dropPeer();
    if (!available) {
      clearTimeout(this.retryTimer);
      this.setState('offline');
    } else {
      this.retries = 0;
      this.setState('reconnecting');
      this.discover();
    }
  }

  /** Call when the active network changes even if internet availability stays true. */
  reconnect(): void {
    if (!this.active || !this.online) return;
    this.dropPeer();
    this.setState('reconnecting');
    this.discover();
  }

  stop(): void {
    this.active = false;
    this.online = false;
    this.signalOnline = false;
    clearTimeout(this.retryTimer);
    this.dropPeer();
    this.options.signaling.stop();
    this.setState('stopped');
  }

  private signal(type: Signal['type'], sdp = ''): void {
    if (!this.active || !this.online || !this.signalOnline) return;
    this.options.signaling.send(
      encodeSignal(
        {
          v: 1,
          from: this.options.identity.publicKey,
          to: this.options.remotePublicKey,
          conversationId: this.options.conversationId,
          type,
          challenge: this.challenge,
          attempt: this.attempt,
          sdp,
        },
        this.options.identity
      )
    );
  }

  private discover(): void {
    if (!this.active || !this.online || this.peer) return;
    if (this.options.role === 'guest') {
      if (!this.challenge) this.challenge = randomId();
      this.signal('request');
    } else this.signal('wake');
    this.scheduleRetry();
  }

  private scheduleRetry(): void {
    clearTimeout(this.retryTimer);
    if (!this.active || !this.online || this.peer) return;
    const delay = Math.min(
      this.timing.max,
      this.timing.min * 2 ** Math.min(this.retries++, 10)
    );
    this.retryTimer = setTimeout(
      () => this.discover(),
      delay * (0.75 + Math.random() * 0.5)
    );
  }

  private async receiveSignal(raw: string): Promise<void> {
    const signal = decodeSignal(
      raw,
      this.options.identity.publicKey,
      this.options.remotePublicKey,
      this.options.conversationId
    );
    if (this.state === 'connected') {
      const isRemoteRestart =
        (signal.type === 'wake' && this.options.role === 'guest') ||
        (signal.type === 'request' && this.options.role === 'host') ||
        (signal.type === 'offer' && this.options.role === 'guest');
      if (isRemoteRestart) {
        this.dropPeer();
        this.setState('reconnecting');
      } else {
        return;
      }
    }
    if (signal.type === 'wake' && this.options.role === 'guest' && !this.peer) {
      // Reuse an outstanding challenge; repeated wakeups must not invalidate an offer.
      if (!this.challenge) this.challenge = randomId();
      this.signal('request');
    } else if (signal.type === 'request' && this.options.role === 'host') {
      if (this.peer && signal.challenge !== this.challenge) {
        this.dropPeer();
        this.setState('reconnecting');
      }
      if (!this.peer) {
        this.challenge = signal.challenge;
        this.attempt = randomId();
        const peer = this.newPeer();
        const generation = this.generation;
        try {
          const host = await this.options.getHostOptions!();
          if (!this.current(peer, generation)) return;
          const sdp = await peer.createOffer(host);
          if (this.current(peer, generation)) this.signal('offer', sdp);
        } catch (error) {
          if (this.current(peer, generation)) this.retry(error);
        }
      }
    } else if (
      signal.type === 'offer' &&
      this.options.role === 'guest' &&
      this.challenge &&
      signal.challenge === this.challenge
    ) {
      if (this.peer && signal.attempt !== this.attempt) {
        this.dropPeer();
        this.setState('reconnecting');
      }
      if (!this.peer) {
        this.attempt = signal.attempt;
        const peer = this.newPeer();
        const generation = this.generation;
        try {
          const sdp = await peer.acceptOffer(signal.sdp);
          if (this.current(peer, generation)) this.signal('answer', sdp);
        } catch (error) {
          if (this.current(peer, generation)) this.retry(error);
        }
      }
    } else if (
      signal.type === 'answer' &&
      this.options.role === 'host' &&
      this.peer &&
      !this.answered &&
      signal.challenge === this.challenge &&
      signal.attempt === this.attempt
    ) {
      this.answered = true;
      const peer = this.peer;
      const generation = this.generation;
      try {
        await peer.acceptAnswer(signal.sdp);
      } catch (error) {
        if (this.current(peer, generation)) this.retry(error);
      }
    }
  }

  private current(peer: SessionTransport, generation: number): boolean {
    return (
      this.active &&
      this.online &&
      this.peer === peer &&
      generation === this.generation
    );
  }

  private newPeer(): SessionTransport {
    clearTimeout(this.retryTimer);
    const peer =
      this.options.createPeer?.() ?? new P2PTcpPeer(this.options.peerOptions);
    this.peer = peer;
    this.answered = false;
    const generation = ++this.generation;
    this.setState('connecting');
    this.unsubs = [
      peer.on('state', (state) => {
        if (this.current(peer, generation) && state === 'connected')
          this.connected();
      }),
      peer.on('error', (error) => {
        if (this.current(peer, generation)) this.retry(error);
      }),
      peer.on('close', () => {
        if (this.current(peer, generation)) this.retry();
      }),
      peer.on('message', (message) => {
        this.inbound = this.inbound
          .then(async () => {
            if (this.current(peer, generation))
              await this.receivePacket(message.payload, peer, generation);
          })
          .catch((error) => {
            if (this.current(peer, generation)) this.retry(error);
          });
      }),
    ];
    this.deadline = setTimeout(() => {
      if (this.current(peer, generation))
        this.retry(new Error('Peer handshake timed out'));
    }, this.timing.handshake);
    return peer;
  }

  private connected(): void {
    clearTimeout(this.deadline);
    this.lastReceived = Date.now();
    this.retries = 0;
    this.setState('connected');
    this.heartbeat = setInterval(() => {
      if (Date.now() - this.lastReceived > this.timing.idle)
        this.retry(new Error('Peer heartbeat timed out'));
      else this.sendPacket({ kind: 'ping' });
    }, this.timing.heartbeat);
    this.flush();
  }

  private sendPacket(packet: { [key: string]: JsonValue }): void {
    if (this.state !== 'connected' || !this.peer) return;
    try {
      this.peer.sendMessage({
        ...packet,
        protocol: 'fprot.chat.v1',
        conversationId: this.options.conversationId,
      });
    } catch (error) {
      this.retry(error);
    }
  }

  private flush(): void {
    if (this.state !== 'connected' || this.inFlight) return;
    const message = this.store?.pending();
    if (!message) return;
    this.inFlight = message.id;
    // One outstanding message bounds buffering and preserves send order.
    this.ackTimer = setTimeout(
      () => this.retry(new Error('Message acknowledgement timed out')),
      this.timing.ack
    );
    this.sendPacket({
      kind: 'message',
      id: message.id,
      payload: message.payload,
      sentAt: message.sentAt,
    });
  }

  private async receivePacket(
    value: JsonValue,
    peer: SessionTransport,
    generation: number
  ): Promise<void> {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error('Invalid chat packet');
    if (
      value.protocol !== 'fprot.chat.v1' ||
      value.conversationId !== this.options.conversationId
    )
      throw new Error('Chat scope mismatch');
    this.lastReceived = Date.now();
    if (value.kind === 'ping') {
      this.sendPacket({ kind: 'pong' });
      return;
    }
    if (value.kind === 'pong') return;
    if (typeof value.id !== 'string' || !/^[A-Za-z0-9_-]{16}$/.test(value.id))
      throw new Error('Invalid message ID');
    if (value.kind === 'ack') {
      if (value.id !== this.inFlight) return;
      await this.store!.acknowledge(value.id);
      this.publishMessages();
      if (!this.current(peer, generation)) return;
      clearTimeout(this.ackTimer);
      this.inFlight = undefined;
      this.flush();
    } else if (value.kind === 'message') {
      validatePayload(value.payload);
      if (typeof value.sentAt !== 'number' || !Number.isFinite(value.sentAt))
        throw new Error('Invalid timestamp');
      await this.store!.add({
        id: value.id,
        payload: value.payload,
        sentAt: value.sentAt,
        direction: 'incoming',
        status: 'delivered',
      });
      this.publishMessages();
      if (this.current(peer, generation))
        this.sendPacket({ kind: 'ack', id: value.id });
    } else throw new Error('Unknown chat packet');
  }

  private dropPeer(): void {
    ++this.generation;
    clearTimeout(this.deadline);
    clearTimeout(this.ackTimer);
    clearInterval(this.heartbeat);
    this.inFlight = undefined;
    this.unsubs.forEach((unsubscribe) => unsubscribe());
    this.unsubs = [];
    const peer = this.peer;
    this.peer = undefined;
    this.challenge = '';
    this.attempt = '';
    peer?.close();
  }

  private retry(error?: unknown): void {
    this.dropPeer();
    if (!this.active || !this.online) return;
    this.setState('reconnecting');
    this.scheduleRetry();
    if (error) this.report(error);
  }

  private setState(state: ConversationState): void {
    this._state = state;
    this.events.emit('state', state);
  }
  private publishMessages(): void {
    this.events.emit('messages', this.messages);
  }
  private report(error: unknown): void {
    this.events.emit(
      'error',
      error instanceof Error ? error : new Error(String(error))
    );
  }
}
