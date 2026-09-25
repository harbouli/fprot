# fprot

> **Encrypted peer-to-peer TCP messaging for React Native, negotiated via WebRTC.**

`fprot` creates private, direct peer-to-peer messaging sessions between mobile devices. WebRTC is used exclusively during connection setup to discover peers, exchange an ephemeral public key, and advertise the TCP endpoint. Once both peers authenticate the TCP stream, **WebRTC is closed and all application messages travel directly over an encrypted raw TCP socket**.

---

## Features

- **Raw TCP Transport**: Built-in native TCP sockets (Swift BSD sockets on iOS, Kotlin `ServerSocket`/`Socket` on Android) carry 100% of application messages. Zero application data flows through WebRTC data channels.
- **Built-in Native Cryptography**: Every frame is authenticated and encrypted natively using X25519 + SHA-256 + AES-256-GCM and RFC 8032 Ed25519 signatures (Apple `CryptoKit` on iOS, Kotlin/JCA on Android) with zero external crypto dependencies.
- **Strict Anti-Replay Sequencing**: Strict sequence numbers reject duplicated, modified, or out-of-order frames.
- **Pinned Identity Keys (MITM-Proof)**: Supports Ed25519 identity keys pinned out-of-band to prevent signaling server spoofing or impersonation attacks.
- **Offline Persistence & Auto-Reconnect**: `ReliableConversation` provides durable local message storage, an offline send queue, delivery receipts (`pending` → `delivered`), and automatic reconnect on network changes.
- **Zero-Dependency Signaling Server**: Includes a turnkey WebSocket signaling coordinator in `server/signaling.mjs`.

For in-depth protocol flowcharts, wire formats, signaling internals, and reliability guarantees, explore the **Multi-Page Documentation Suite**:
- **[Part 1: Master Architecture & Protocol Overview (`docs/HOW_IT_WORKS.md`)](docs/HOW_IT_WORKS.md)**
- **[Part 2: Signaling Deep Dive (`docs/SIGNALING_DEEP_DIVE.md`)](docs/SIGNALING_DEEP_DIVE.md)**
- **[Part 3: Reliability, Storage & Resilience (`docs/RELIABILITY_AND_RESILIENCE.md`)](docs/RELIABILITY_AND_RESILIENCE.md)**
- **[Part 4: Cryptography & Wire Protocol Reference (`docs/CRYPTOGRAPHY_AND_WIRE_PROTOCOL.md`)](docs/CRYPTOGRAPHY_AND_WIRE_PROTOCOL.md)**
- **[Part 5: Custom Backend Integration Guide (`docs/CUSTOM_BACKEND_INTEGRATION.md`)](docs/CUSTOM_BACKEND_INTEGRATION.md)**

---

## Installation

### 1. Install Package and Peer Dependencies

In your React Native project root:

```sh
# Using npm:
npm install @harbouli/fprot react-native-webrtc @react-native-async-storage/async-storage react-native-keychain @react-native-community/netinfo

# Using Yarn:
yarn add @harbouli/fprot react-native-webrtc @react-native-async-storage/async-storage react-native-keychain @react-native-community/netinfo
```

### 2. iOS Configuration

1. In your `ios/Podfile`, ensure New Architecture is enabled and set the minimum deployment target to at least `15.1`:
   ```ruby
   ENV['RCT_NEW_ARCH_ENABLED'] = '1'

   post_install do |installer|
     installer.pods_project.targets.each do |target|
       target.build_configurations.each do |config|
         if config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'].to_f < 15.1
           config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '15.1'
         end
       end
     end
   end
   ```

2. In `ios/<YourAppName>/Info.plist`, add permission for local network discovery:
   ```xml
   <key>NSLocalNetworkUsageDescription</key>
   <string>Connect to peer devices and signaling server on the local network.</string>
   ```

3. Install pods:
   ```sh
   cd ios && pod install
   ```

### 3. Android Configuration

In `android/app/src/main/AndroidManifest.xml`, ensure the following permissions are present:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
```

---

## Integration Guide

`fprot` provides two layers depending on your requirements:

### Option A: `ReliableConversation` (Recommended for Chat Apps)

Handles identity pinning, durable encrypted storage, offline queueing, delivery receipts, and automatic reconnection:

```tsx
import React, { useEffect, useState } from 'react';
import { View, Text, TextInput, Button, FlatList } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Keychain from 'react-native-keychain';
import NetInfo from '@react-native-community/netinfo';
import {
  ReliableConversation,
  WebSocketSignaling,
  loadOrCreateIdentity,
  createEncryptedStorage,
  type ChatMessage,
  type ConversationState,
} from 'fprot';

// 1. Key-value store backed by iOS Keychain / Android Keystore
const secureStorage = {
  async getItem(key: string) {
    const creds = await Keychain.getGenericPassword({ service: key });
    return creds ? creds.password : null;
  },
  async setItem(key: string, value: string) {
    await Keychain.setGenericPassword('fprot', value, { service: key });
  },
};

export function ChatRoom({ friendPublicKey, isHost }: { friendPublicKey: string; isHost: boolean }) {
  const [conversation, setConversation] = useState<ReliableConversation | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [state, setState] = useState<ConversationState>('stopped');
  const [draft, setDraft] = useState('');

  useEffect(() => {
    let session: ReliableConversation;

    async function init() {
      // 2. Load or create long-term Ed25519 identity key
      const identity = await loadOrCreateIdentity(secureStorage);

      // 3. Create encrypted offline store for chat history
      const storage = await createEncryptedStorage(AsyncStorage, secureStorage);

      // 4. Initialize session
      session = new ReliableConversation({
        identity,
        remotePublicKey: friendPublicKey,
        conversationId: 'our-secret-room',
        role: isHost ? 'host' : 'guest',
        storage,
        signaling: new WebSocketSignaling({
          url: 'wss://signal.yourdomain.com:8787', // Use ws:// only on trusted development LAN
          token: 'your-secure-shared-signaling-token-32chars',
          identity,
          allowInsecureLocalDevelopment: true, // Set to true if testing with local ws://
        }),
        getHostOptions: async () => {
          const network = await NetInfo.fetch();
          return {
            advertiseHost: network.details?.ipAddress || '192.128.0.0',
          };
        },
      });

      session.on('state', setState);
      session.on('messages', setMessages);
      await session.start();
      setConversation(session);
    }

    init();
    return () => {
      session?.stop();
    };
  }, [friendPublicKey, isHost]);

  return (
    <View style={{ flex: 1, padding: 20 }}>
      <Text>Status: {state}</Text>
      
      <FlatList
        data={messages}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <Text>
            {item.direction === 'outgoing' ? 'You: ' : 'Friend: '}
            {String(item.payload)} [{item.status}]
          </Text>
        )}
      />

      <TextInput
        placeholder="Type a message (queued if offline)..."
        value={draft}
        onChangeText={setDraft}
      />
      
      <Button
        title="Send"
        onPress={() => {
          if (conversation && draft.trim()) {
            conversation.sendMessage(draft.trim());
            setDraft('');
          }
        }}
      />
    </View>
  );
}
```

---

### Option B: `P2PTcpPeer` (Low-Level Transport)

For single-session connections where you exchange the SDP offer/answer manually (via QR code, Bluetooth, or your own custom API):

```ts
import { P2PTcpPeer } from 'fprot';

// 1. Device A (Host):
const host = new P2PTcpPeer({
  iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
});

host.on('state', (state) => console.log('Host state:', state));
host.on('message', (msg) => console.log('Received:', msg.payload));

const offer = await host.createOffer({
  advertiseHost: '192.168.1.42', // Host's reachable IP
  port: 0,                      // 0 = OS selects free port
});

// Transfer `offer` string to Device B via your signaling method...

// 2. Device B (Guest):
const guest = new P2PTcpPeer();
guest.on('message', (msg) => console.log('Received:', msg.payload));

const answer = await guest.acceptOffer(offer);

// Transfer `answer` string back to Device A...

// 3. Back on Device A:
await host.acceptAnswer(answer);

// When both reach 'connected':
host.sendMessage({ text: 'Hello from Host over encrypted TCP!' });
guest.sendMessage({ text: 'Hello back from Guest!' });
```

---

## Starting the Signaling Server

`fprot` includes a lightweight, secure signaling broker located in `server/signaling.mjs`.

To start it:

```sh
# Requires a token of at least 32 characters
FPROT_SIGNAL_TOKEN="my-super-secret-signaling-token-32chars" \
FPROT_SIGNAL_HOST="0.0.0.0" \
FPROT_SIGNAL_PORT=8787 \
yarn signaling
```

---

## Running the Example Application

The repository includes a ready-to-test React Native example app in `example/`:

1. **Start the signaling server** in a terminal:
   ```sh
   FPROT_SIGNAL_TOKEN="my-super-secret-signaling-token-32chars" FPROT_SIGNAL_HOST="0.0.0.0" FPROT_SIGNAL_PORT=8787 yarn signaling
   ```
2. **Start Metro Bundler**:
   ```sh
   yarn example start
   ```
3. **Run on Simulators or Devices**:
   ```sh
   # Device A:
   yarn example ios --simulator="iPhone 17 Pro"

   # Device B:
   yarn example ios --simulator="iPhone 17"
   ```
4. **Pairing in App**:
   - Cross-paste the public keys displayed at the top of each screen into "Friend's public identity".
   - Select **Host** on Device A and **Guest** on Device B.
   - Enter your Mac's LAN IP (`192.168.1.x`) into the Host address field.
   - Tap **Save pairing & connect** on both devices.

---

## Using Your Own Backend

If you already have a backend (Node.js, Socket.io, Firebase, Supabase, Go, Python, etc.) and want to integrate `fprot` into your own authentication and routing infrastructure, see:

👉 **[Custom Backend Integration Guide (docs/CUSTOM_BACKEND_INTEGRATION.md)](docs/CUSTOM_BACKEND_INTEGRATION.md)**

It includes:
- How to implement a custom `SignalTransport` in ~20 lines of code.
- Ready-to-copy examples for **Socket.io / Node.js** and **Supabase Realtime**.
- How to use simple HTTP REST endpoints for offer/answer exchange.
- Security best practices and APNs/FCM push notification triggers.

---

## Architecture & How It Works

See [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) for complete technical documentation, including:
- High-level architecture and component diagrams
- Cryptographic details (X25519 ECDH, `AES-256-GCM` authenticated encryption, RFC 8032 Ed25519 signatures)
- Complete sequence diagrams for connection, WebRTC teardown, and TCP framing
- NAT traversal requirements and relay architectures

---

## License

MIT
