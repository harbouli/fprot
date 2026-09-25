import type {
  JsonValue,
  P2PMessage,
  P2PTcpPeerOptions,
  PeerEventMap,
  TcpHostOptions,
  Unsubscribe,
} from '../types';

/** setItem must atomically replace a value and resolve only after persistence. */
export interface KeyValueStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
}

/** Store this only in Keychain/Keystore or an equivalent secret store. */
export interface PeerIdentity {
  publicKey: string;
  privateKey: string;
}

export interface ChatMessage extends P2PMessage {
  direction: 'incoming' | 'outgoing';
  status: 'pending' | 'delivered';
}

export type ConversationState =
  'stopped' | 'offline' | 'reconnecting' | 'connecting' | 'connected';

export interface SignalTransport {
  start(handlers: {
    onMessage: (message: string) => void;
    onOnline: (online: boolean) => void;
  }): void;
  /** Returns false if unavailable. Does not buffer obsolete offers. */
  send(message: string): boolean;
  stop(): void;
}

export interface SessionTransport {
  on<K extends keyof PeerEventMap>(
    event: K,
    listener: (value: PeerEventMap[K]) => void
  ): Unsubscribe;
  createOffer(host: TcpHostOptions): Promise<string>;
  acceptOffer(offer: string): Promise<string>;
  acceptAnswer(answer: string): Promise<void>;
  sendMessage(payload: JsonValue): string;
  close(): void;
}

export interface ReliableConversationOptions {
  identity: PeerIdentity;
  /** Pinned key exchanged through a trusted channel when pairing. Never auto-replaced. */
  remotePublicKey: string;
  /** Both participants must use the same stable conversation ID. */
  conversationId: string;
  role: 'host' | 'guest';
  /** Called for every attempt so network/address changes can be reflected. */
  getHostOptions?: () => TcpHostOptions | Promise<TcpHostOptions>;
  storage: KeyValueStorage;
  signaling: SignalTransport;
  peerOptions?: P2PTcpPeerOptions;
  retryMinMs?: number;
  retryMaxMs?: number;
  handshakeTimeoutMs?: number;
  heartbeatMs?: number;
  idleTimeoutMs?: number;
  ackTimeoutMs?: number;
  /** Injectable for integration tests or a compatible TCP session implementation. */
  createPeer?: () => SessionTransport;
}

export interface ConversationEvents {
  state: ConversationState;
  messages: ChatMessage[];
  error: Error;
}
