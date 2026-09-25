# Complete API & Utilities Reference (`fprot`)

> **Documentation Navigation**
> - **[GitHub Pages Interactive Portal (`index.html`)](./index.html)**
> - **[Part 1: Master Architecture & Overview (`HOW_IT_WORKS.md`)](./HOW_IT_WORKS.md)**
> - **[Part 2: Signaling Deep Dive (`SIGNALING_DEEP_DIVE.md`)](./SIGNALING_DEEP_DIVE.md)**
> - **[Part 3: Reliability, Storage & Resilience (`RELIABILITY_AND_RESILIENCE.md`)](./RELIABILITY_AND_RESILIENCE.md)**
> - **[Part 4: Cryptography & Wire Protocol Reference (`CRYPTOGRAPHY_AND_WIRE_PROTOCOL.md`)](./CRYPTOGRAPHY_AND_WIRE_PROTOCOL.md)**
> - **[Part 5: Custom Backend Integration (`CUSTOM_BACKEND_INTEGRATION.md`)](./CUSTOM_BACKEND_INTEGRATION.md)**
> - **[Part 6: Complete API & Utilities Reference (`API_REFERENCE.md`)](./API_REFERENCE.md)** *(Current Page)*

---

Every class, cryptographic helper, storage wrapper, signaling encoder/decoder, stream framing utility, constant, and TypeScript interface built into `fprot` is exported directly from the root package (`import { ... } from 'fprot'`) so you can compose custom workflows, custom transports, or standalone cryptographic protocols with maximum flexibility.

```ts
import {
  // Core Classes
  ReliableConversation,
  P2PTcpPeer,
  WebSocketSignaling,
  MessageStore,
  LineDecoder,
  EventBus,

  // Identity & Storage Utilities
  loadOrCreateIdentity,
  validatePublicKey,
  validateIdentity,
  sign,
  verify,
  conversationStorageKey,
  createEncryptedStorage,
  validatePayload,

  // Low-Level Session Cryptography (libsodium)
  createSessionKeys,
  exportPublicKey,
  importPublicKey,
  encryptJson,
  decryptJson,
  randomId,

  // Cross-Platform / Native Cryptographic Primitives & Base64URL
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
  NONCE_BYTES,

  // Cross-Platform / Native TCP Socket & Server Wrapper
  TcpSocket,

  // Signaling Protocol Utilities
  encodeSignal,
  decodeSignal,
  encodeReliableSignal,
  decodeReliableSignal,
  encodePeerSignal,
  decodePeerSignal,
  encodeSdpSignal,
  decodeSdpSignal,

  // Constants
  MAX_MESSAGE_BYTES,
  MAX_MESSAGES,
  SIGNAL_VERSION,
} from 'fprot';
```

---

## 1. Core Classes

### 1.1 `ReliableConversation`
Persistent, self-healing conversation supervisor that manages `MessageStore` persistence, Ed25519 identity verification, Stop-and-Wait ARQ acknowledgments (`pending` $\rightarrow$ `delivered`), encrypted heartbeats, and automatic `P2PTcpPeer` reconnection across network switches.

#### Constructor
```ts
new ReliableConversation(options: ReliableConversationOptions)
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `identity` | `PeerIdentity` | *Required* | Local device's long-term Ed25519 keypair (`{ publicKey, privateKey }`). |
| `remotePublicKey` | `string` | *Required* | Pinned 32-byte base64url Ed25519 public key of the remote peer. |
| `conversationId` | `string` | *Required* | Shared conversation identifier (`1–128` characters). |
| `role` | `'host' \| 'guest'` | *Required* | One peer must act as `'host'` (listens on TCP) and the other as `'guest'` (connects to TCP). |
| `getHostOptions` | `() => TcpHostOptions \| Promise<TcpHostOptions>` | *Required if `'host'`* | Invoked on every connection attempt to resolve the Host's current reachable IP/port. |
| `storage` | `KeyValueStorage` | *Required* | Async key-value store (typically wrapped with `createEncryptedStorage`). |
| `signaling` | `SignalTransport` | *Required* | Out-of-band signaling transport (`WebSocketSignaling` or custom). |
| `peerOptions` | `P2PTcpPeerOptions` | `undefined` | Passed to underlying `P2PTcpPeer` instances (`maxFrameBytes` must be $\ge 32768$). |
| `retryMinMs` | `number` | `1000` | Minimum base reconnect backoff delay in milliseconds. |
| `retryMaxMs` | `number` | `30000` | Maximum base reconnect backoff delay in milliseconds. |
| `handshakeTimeoutMs` | `number` | `45000` | Deadline for a spawned `P2PTcpPeer` to reach `'connected'`. |
| `heartbeatMs` | `number` | `10000` | Interval between encrypted application-layer `ping` packets. |
| `idleTimeoutMs` | `number` | `35000` | Maximum silence duration before declaring the TCP peer dead (must be `> heartbeatMs`). |
| `ackTimeoutMs` | `number` | `10000` | Time to wait for a message delivery `ack` before reconnecting and retrying. |
| `createPeer` | `() => SessionTransport` | `undefined` | Optional factory for dependency injection or custom transports. |

#### Properties & Methods
- **`conversation.state: ConversationState`**: Current state (`'stopped' | 'offline' | 'reconnecting' | 'connecting' | 'connected'`).
- **`conversation.messages: ChatMessage[]`**: Deep-cloned snapshot of all stored incoming and outgoing messages.
- **`await conversation.start(): Promise<void>`**: Initializes libsodium, validates keys, loads `MessageStore` from disk, starts signaling, and begins peer discovery.
- **`await conversation.sendMessage(payload: JsonValue): Promise<string>`**: Validates and persists `payload` to disk (`status: 'pending'`), emits updated `messages` to listeners, flushes the send queue if connected, and returns the 16-char message `id`.
- **`conversation.setAvailable(available: boolean): void`**: Notifies the conversation of foreground/background transitions or internet availability changes. Passing `false` drops the active peer and enters `'offline'`; passing `true` resets backoff retries to `0` and immediately discovers the partner.
- **`conversation.reconnect(): void`**: Immediately drops the current TCP peer and re-runs discovery (call when the device's local IP address changes).
- **`conversation.stop(): void`**: Stops signaling, closes the active peer, clears all timers, and transitions to `'stopped'`.
- **`conversation.on(event, callback): Unsubscribe`**: Subscribes to `'state'`, `'messages'`, or `'error'` events and returns an unsubscribe function.

---

### 1.2 `P2PTcpPeer`
Low-level, single-session transport that negotiates ephemeral X25519 keys and a TCP endpoint over an ordered WebRTC data channel (`p2p-tcp-control`), transitions traffic to an authenticated raw TCP stream, and closes WebRTC.

#### Constructor
```ts
new P2PTcpPeer(options?: P2PTcpPeerOptions)
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `iceServers` | `IceServer[]` | `[]` | STUN/TURN servers for WebRTC candidate gathering. |
| `iceGatheringTimeoutMs` | `number` | `12000` | Timeout in ms for non-trickle ICE candidate gathering. |
| `tcpConnectTimeoutMs` | `number` | `10000` | Timeout in ms for the Guest's direct TCP socket connection. |
| `maxFrameBytes` | `number` | `1048576` (1 MB) | Maximum allowed byte length for an encrypted TCP line (`\n`-delimited). |

#### Properties & Methods
- **`peer.state: PeerState`**: `'idle' | 'signaling' | 'negotiating' | 'tcp-connecting' | 'connected' | 'closed' | 'failed'`.
- **`await peer.createOffer(host: TcpHostOptions): Promise<string>`**: Starts a local TCP listener, generates ephemeral X25519 keys, gathers WebRTC ICE candidates, and returns a JSON-encoded offer string.
- **`await peer.acceptOffer(offer: string): Promise<string>`**: Applies the Host's offer, generates ephemeral X25519 keys, gathers ICE candidates, and returns a JSON-encoded answer string.
- **`await peer.acceptAnswer(answer: string): Promise<void>`**: Applies the Guest's answer on the Host, triggering the WebRTC data channel handshake and automatic TCP connection.
- **`peer.sendMessage(payload: JsonValue): string`**: Encrypts and writes a JSON payload to the TCP stream with the next monotonic sequence number. Returns the generated 16-char message ID.
- **`peer.close(): void`**: Closes the TCP socket, listening server, and WebRTC channels, and zeroes the ephemeral X25519 private key in memory (`privateKey.fill(0)`).
- **`peer.on(event, listener): Unsubscribe`**: Subscribes to `'state'`, `'message'`, `'error'`, or `'close'`.

---

### 1.3 `WebSocketSignaling`
Authenticated, auto-reconnecting WebSocket client implementing `SignalTransport` for `server/signaling.mjs`.

```ts
const signaling = new WebSocketSignaling({
  url: 'wss://signal.example.com:8787',
  token: 'minimum-32-character-shared-secret-token',
  identity,
  allowInsecureLocalDevelopment: false, // Set true only for ws:// on a trusted LAN
});
```
- **`signaling.start(handlers)`**: Connects to the broker, responds to the server's 64-hex-char `challenge` nonce with an Ed25519 signature over `fprot.broker.v1:${nonce}`, and invokes `handlers.onOnline(true)` once `{ type: "ready" }` arrives.
- **`signaling.send(message: string): boolean`**: Wraps the signed signal envelope in `{ type: "signal", data: message }` and sends over WebSocket. Returns `false` if offline or unauthenticated.
- **`signaling.stop(): void`**: Cancels reconnect timers and closes the WebSocket.

---

### 1.4 `MessageStore`
Single-writer, write-ahead persistent message journal with automatic deduplication and strict JSON validation. You can instantiate `MessageStore` directly if building custom reliable protocols!

```ts
const store = new MessageStore(encryptedStorage, 'my-custom-store-key');
await store.load();
```
- **`await store.load(): Promise<void>`**: Loads and validates stored messages from `KeyValueStorage` (verifying schema `v: 1`, ID format, finite timestamps, payload purity, and uniqueness).
- **`store.snapshot(): ChatMessage[]`**: Returns a deep copy of all stored messages.
- **`store.pending(): ChatMessage | undefined`**: Returns the oldest outgoing message with `status === 'pending'`.
- **`await store.add(message: ChatMessage): Promise<boolean>`**: Atomically persists a new message to disk before updating memory. Returns `false` if an identical `(direction, id, sentAt, payload)` already exists (idempotent deduplication). Throws if an ID is reused with different contents or if storage reaches `MAX_MESSAGES` (`2000`).
- **`await store.acknowledge(id: string): Promise<void>`**: Marks an outgoing message with matching `id` as `'delivered'` and persists the updated snapshot.

---

### 1.5 `LineDecoder`
Stream framing utility that splits arbitrary TCP/stream chunks on `\n` boundaries while enforcing a strict maximum frame size to prevent buffer-overflow Denial-of-Service attacks.

```ts
const decoder = new LineDecoder(65536); // 64 KB max line size
socket.on('data', (chunk) => {
  for (const line of decoder.push(String(chunk))) {
    console.log('Complete framed line:', line);
  }
});
```
- **`decoder.push(chunk: string): string[]`**: Appends `chunk` to the internal buffer, throws immediately if any line or un-terminated buffer exceeds `maxBytes`, and returns an array of complete non-empty lines.

---

### 1.6 `EventBus<Events>`
Lightweight, type-safe publish/subscribe event emitter used internally by `P2PTcpPeer` and `ReliableConversation`, exported for custom transports and application state management.

```ts
interface MyEvents {
  status: 'online' | 'offline';
  count: number;
}
const bus = new EventBus<MyEvents>();
const unsub = bus.on('count', (n) => console.log('Count is', n));
bus.emit('count', 42);
unsub();
bus.clear();
```

---

## 2. Identity & Encrypted Storage Utilities (`src/reliable/identity.ts`)

### `loadOrCreateIdentity(secureStorage: KeyValueStorage): Promise<PeerIdentity>`
Loads an existing Ed25519 keypair from `secureStorage.getItem('fprot.identity.v1')`, validates it via a live sign/verify self-test, or generates a brand-new Ed25519 keypair (`crypto_sign_keypair()`) and saves it to `secureStorage`.

### `validatePublicKey(key: string): void`
Validates that `key` is a canonical base64url-encoded 32-byte Ed25519 public key. Throws `Error('Invalid Ed25519 peer public key')` if malformed or non-canonical.

### `validateIdentity(identity: PeerIdentity): void`
Validates both `identity.publicKey` (32 bytes) and `identity.privateKey` (64 bytes) and performs a live cryptographic self-check (`verify('fprot.identity.check', sign('fprot.identity.check', identity), identity.publicKey)`).

### `sign(body: string, identity: PeerIdentity): string`
Computes a detached 64-byte Ed25519 signature (`crypto_sign_detached`) over UTF-8 string `body` using `identity.privateKey` and returns it as a base64url string.

### `verify(body: string, signature: string, publicKey: string): boolean`
Verifies a base64url Ed25519 `signature` over `body` against a base64url 32-byte `publicKey`. Returns `true` if valid, `false` on any verification or decoding failure (never throws).

### `conversationStorageKey(id: string, local: string, remote: string): string`
Computes a deterministic, collision-resistant storage key (`fprot.chat.<base64url_blake2b_256>`) using libsodium `crypto_generichash` (32-byte BLAKE2b) over `JSON.stringify([id, local, remote])`.

### `createEncryptedStorage(storage: KeyValueStorage, secureStorage: KeyValueStorage): Promise<KeyValueStorage>`
Wraps any unencrypted `KeyValueStorage` (such as `AsyncStorage`) with libsodium `crypto_secretbox_easy` (XSalsa20-Poly1305) authenticated encryption.
- Automatically generates and persists a 32-byte master key in `secureStorage` (`fprot.storage-key.v1`).
- Binds the record `name` inside the encrypted payload (`{ name, value }`) so encrypted blobs cannot be swapped across keys.

### `validatePayload(payload: unknown): asserts payload is JsonValue`
Asserts that `payload` is pure JSON (no `undefined`, `NaN`, `Infinity`, `function`, or `symbol` properties) and that its serialized JSON string is at most `2,730` characters (`MAX_MESSAGE_BYTES / 6`).

---

## 3. Low-Level Session Cryptography Utilities (`src/internal/crypto.ts`)

### `createSessionKeys(): Promise<SessionKeys>`
Initializes libsodium (`await ready`) and generates an ephemeral X25519 Diffie-Hellman keypair (`crypto_box_keypair()`) returning `{ publicKey: Uint8Array, privateKey: Uint8Array }` (each 32 bytes).

### `exportPublicKey(key: Uint8Array): string`
Encodes a binary `Uint8Array` (key, nonce, or signature) into an unpadded URL-safe Base64 string (`base64_variants.URLSAFE_NO_PADDING`).

### `importPublicKey(key: string): Uint8Array`
Decodes an unpadded URL-safe Base64 string back into a `Uint8Array`.

### `encryptJson(value: unknown, remotePublicKey: Uint8Array, localPrivateKey: Uint8Array): EncryptedFrame`
Serializes `value` to JSON, generates a random 24-byte nonce (`randombytes_buf(crypto_box_NONCEBYTES)`), encrypts and authenticates the plaintext using `crypto_box_easy` (X25519 + XSalsa20-Poly1305), and returns `{ v: 1, nonce: string, ciphertext: string }`.

### `decryptJson<T>(frame: EncryptedFrame, remotePublicKey: Uint8Array, localPrivateKey: Uint8Array): T`
Verifies the 16-byte Poly1305 MAC and decrypts an `EncryptedFrame` using `crypto_box_open_easy`, returning the parsed JSON value typed as `T`. Throws if the frame is tampered with or invalid.

### `randomId(): string`
Generates 12 cryptographically secure random bytes (`96 bits` of entropy via `randombytes_buf(12)`) and returns them as a 16-character base64url string (`[A-Za-z0-9_-]{16}`).

---

## 4. Signaling Protocol Encoders & Decoders

### `encodeSignal(signal: Signal, identity: PeerIdentity): string` *(also exported as `encodeReliableSignal`)*
Serializes a `Signal` object (`wake | request | offer | answer`) into `body`, signs `fprot.signaling.v1:${body}` with `identity`, and returns the JSON string `{ body, signature }`.

### `decodeSignal(raw: string, localKey: string, remoteKey: string, conversationId: string): Signal` *(also exported as `decodeReliableSignal`)*
Verifies the size limit (`<= 128 KB`), Ed25519 signature (`fprot.signaling.v1:`), sender identity (`from === remoteKey`), recipient identity (`to === localKey`), `conversationId`, and `challenge`/`attempt` 16-character format, returning the validated `Signal`.

### `encodePeerSignal(type: 'offer' | 'answer', sdp: string): string` *(also exported as `encodeSdpSignal`)*
Low-level helper used by `P2PTcpPeer` that wraps a raw WebRTC SDP string into `{"v":1,"type":"offer"|"answer","sdp":"..."}`.

### `decodePeerSignal(input: string, expectedType: 'offer' | 'answer'): SignalEnvelope` *(also exported as `decodeSdpSignal`)*
Parses and validates a version-1 SDP envelope string produced by `encodePeerSignal`.

---

## 5. Cross-Platform Native Cryptographic Primitives & Base64URL (`src/internal/nativeCrypto.ts`)

These utilities delegate directly to `NativeModules.FprotNative` on iOS/Android when present and automatically fall back to pure Node.js `node:crypto` in Jest/Node environments.

### `toBase64Url(bytes: Uint8Array): string` & `fromBase64Url(str: string): Uint8Array`
Zero-dependency RFC 4648 §5 Base64URL encoder and decoder without `=` padding. Rejects non-canonical lengths or invalid characters.

### `randomBytes(size: number): Uint8Array` & `sha256(utf8Input: string): Uint8Array`
Generates `size` cryptographically secure random bytes or computes a 32-byte SHA-256 digest over a UTF-8 string.

### `boxKeypair()` / `boxSeal(plaintextUtf8, nonce12, remotePub32, localPriv32)` / `boxOpen(ciphertextWithTag, nonce12, remotePub32, localPriv32)`
X25519 Diffie-Hellman authenticated encryption (`fprot.box.v1` key derivation with low-order point and self-reflection rejection).

### `signKeypair()` / `signDetached(messageUtf8, secretKey64)` / `verifyDetached(messageUtf8, signature64, publicKey32)`
Ed25519 key generation (32-byte public key + 64-byte secret key), 64-byte detached signing, and boolean signature verification.

### `secretboxKeygen()` / `secretboxSeal(plaintextUtf8, nonce12, key32)` / `secretboxOpen(ciphertextWithTag, nonce12, key32)`
Symmetric authenticated encryption (256-bit key, 12-byte `NONCE_BYTES` nonce, and 16-byte authentication tag).

---

## 6. Cross-Platform Raw TCP Socket & Server (`src/internal/tcp.ts`)

### `TcpSocket.createServer(connectionListener)` & `TcpSocket.createConnection(options, connectListener)`
Unified TCP server and client abstraction (`TcpSocketServer` and `TcpSocketConnection`) that routes through `NativeModules.FprotNative` on React Native or Node's `node:net` in Node/test environments, with automatic data buffering until `markReadyForData()` completes.

---

## 7. Exported Constants

| Constant | Value | Description |
| :--- | :---: | :--- |
| `MAX_MESSAGE_BYTES` | `16384` (`16 * 1024`) | Base byte constant used to bound serialized payload length (`MAX_MESSAGE_BYTES / 6 = 2730` chars). |
| `MAX_MESSAGES` | `2000` | Maximum number of messages stored in a single `MessageStore` conversation before archiving is required. |
| `SIGNAL_VERSION` | `1` | Protocol version number for `P2PTcpPeer` SDP signaling envelopes. |
| `NONCE_BYTES` | `12` | Nonce byte length used by `nativeCrypto` (`boxSeal` / `secretboxSeal`). |
