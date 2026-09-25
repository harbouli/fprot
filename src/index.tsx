// Core Peer & Conversation Classes
export { P2PTcpPeer } from './P2PTcpPeer';
export { ReliableConversation } from './reliable/ReliableConversation';
export { WebSocketSignaling } from './reliable/WebSocketSignaling';

// Identity & Local Encrypted Storage Utilities
export {
  loadOrCreateIdentity,
  validatePublicKey,
  validateIdentity,
  sign,
  verify,
  conversationStorageKey,
  createEncryptedStorage,
} from './reliable/identity';

// Durable Message Store & Payload Validation Utilities
export {
  MessageStore,
  validatePayload,
  MAX_MESSAGE_BYTES,
  MAX_MESSAGES,
} from './reliable/MessageStore';

// Reliable Signaling Protocol Envelopes & Signature Verification
export {
  encodeSignal,
  decodeSignal,
  encodeSignal as encodeReliableSignal,
  decodeSignal as decodeReliableSignal,
} from './reliable/SignalProtocol';
export type { Signal } from './reliable/SignalProtocol';

// Low-Level Session Cryptography & Random ID Utilities (libsodium)
export {
  createSessionKeys,
  exportPublicKey,
  importPublicKey,
  encryptJson,
  decryptJson,
  randomId,
} from './internal/crypto';
export type { SessionKeys, EncryptedFrame } from './internal/crypto';

// Native / Cross-Platform Cryptographic Primitives & Base64URL Utilities
export {
  NONCE_BYTES,
  toBase64Url,
  fromBase64Url,
  randomBytes,
  sha256,
  boxKeypair,
  boxSeal,
  boxOpen,
  signKeypair,
  signDetached,
  verifyDetached,
  secretboxKeygen,
  secretboxSeal,
  secretboxOpen,
} from './internal/nativeCrypto';

// Native / Cross-Platform Raw TCP Socket & Server Utilities
export { TcpSocket } from './internal/tcp';
export type {
  TcpListenOptions,
  TcpConnectOptions,
  TcpSocketConnection,
  TcpSocketServer,
} from './internal/tcp';

// Low-Level WebRTC SDP Offer/Answer Envelope Helpers
export {
  SIGNAL_VERSION,
  encodeSignal as encodePeerSignal,
  decodeSignal as decodePeerSignal,
  encodeSignal as encodeSdpSignal,
  decodeSignal as decodeSdpSignal,
} from './internal/signaling';
export type { SignalEnvelope } from './internal/signaling';

// Stream Framing & Event Utilities
export { LineDecoder } from './internal/LineDecoder';
export { EventBus } from './internal/EventBus';

// TypeScript Interfaces & Types
export type { WebSocketSignalingOptions } from './reliable/WebSocketSignaling';
export type {
  PeerIdentity,
  KeyValueStorage,
  ChatMessage,
  ConversationState,
  ConversationEvents,
  ReliableConversationOptions,
  SignalTransport,
  SessionTransport,
} from './reliable/types';
export type {
  IceServer,
  JsonPrimitive,
  JsonValue,
  P2PMessage,
  P2PTcpPeerOptions,
  PeerEventMap,
  PeerState,
  TcpHostOptions,
  Unsubscribe,
} from './types';
