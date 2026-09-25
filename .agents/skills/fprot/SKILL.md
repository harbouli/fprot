---
name: fprot
description: >-
  Comprehensive guide and procedural runbook for integrating, developing, testing,
  and troubleshooting applications using fprot (authenticated, encrypted peer-to-peer TCP
  messaging negotiated via WebRTC for React Native). Use whenever working with P2PTcpPeer,
  ReliableConversation, custom backend signaling, libsodium cryptography, or native mobile builds.
---

# fprot Skill Guide

`fprot` is an encrypted, authenticated peer-to-peer TCP messaging framework for React Native applications. WebRTC is used exclusively during connection setup to discover network endpoints and exchange ephemeral public keys. Once authenticated over a raw TCP socket, the WebRTC session terminates and all traffic flows directly across TCP with libsodium `crypto_box` encryption.

---

## 1. System Architecture

The library is organized into two primary tiers:

1. **Low-Level Transport (`P2PTcpPeer`)**:
   - Manages one ephemeral peer-to-peer session.
   - Collects non-trickle ICE candidates.
   - Negotiates TCP endpoints over an ephemeral WebRTC data channel (`p2p-tcp-control`).
   - Establishes a direct TCP socket and verifies mutual identity using libsodium `crypto_box`.
   - Closes WebRTC once TCP is verified; frames application messages with newlines (`\n`).

2. **Resilient Application Layer (`ReliableConversation`)**:
   - Pinned long-term Ed25519 identity keys (`loadOrCreateIdentity`).
   - Durable encrypted storage for message history and offline queues (`MessageStore`).
   - End-to-end signal signing and verification (`SignalProtocol`).
   - Automated reconnection, network change handling, and heartbeat monitoring.
   - Pluggable signaling via `SignalTransport` (`WebSocketSignaling`, Socket.io, Supabase, etc.).

---

## 2. Quick Integration Runbook

### Step 1: Install Dependencies

```sh
npm install fprot react-native-webrtc react-native-tcp-socket react-native-libsodium @react-native-async-storage/async-storage react-native-keychain @react-native-community/netinfo
```

### Step 2: Native Configuration

#### iOS (`ios/Podfile`)
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

In `Info.plist`:
```xml
<key>NSLocalNetworkUsageDescription</key>
<string>Connect directly to paired devices for encrypted peer-to-peer chat.</string>
```

#### Android (`android/app/src/main/AndroidManifest.xml`)
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
```

---

## 3. Implementation Pattern (`ReliableConversation`)

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

const secureStorage = {
  async getItem(key: string) {
    const creds = await Keychain.getGenericPassword({ service: key });
    return creds ? creds.password : null;
  },
  async setItem(key: string, value: string) {
    await Keychain.setGenericPassword('fprot', value, { service: key });
  },
};

export function ChatScreen({ friendPublicKey, isHost }: { friendPublicKey: string; isHost: boolean }) {
  const [chat, setChat] = useState<ReliableConversation | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [state, setState] = useState<ConversationState>('stopped');
  const [text, setText] = useState('');

  useEffect(() => {
    let conversation: ReliableConversation;

    async function init() {
      const identity = await loadOrCreateIdentity(secureStorage);
      const storage = await createEncryptedStorage(AsyncStorage, secureStorage);

      conversation = new ReliableConversation({
        identity,
        remotePublicKey: friendPublicKey,
        conversationId: 'main-chat',
        role: isHost ? 'host' : 'guest',
        storage,
        signaling: new WebSocketSignaling({
          url: 'wss://signal.yourdomain.com:8787',
          token: 'your-secure-shared-signaling-token-32-chars-min',
          identity,
        }),
        getHostOptions: async () => {
          const network = await NetInfo.fetch();
          return {
            advertiseHost: network.details?.ipAddress || '192.128.0.0',
          };
        },
      });

      conversation.on('state', setState);
      conversation.on('messages', setMessages);
      await conversation.start();
      setChat(conversation);
    }

    init();
    return () => {
      conversation?.stop();
    };
  }, [friendPublicKey, isHost]);

  return (
    <View style={{ flex: 1, padding: 16 }}>
      <Text>Status: {state}</Text>
      <FlatList
        data={messages}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <Text>{item.direction === 'outgoing' ? 'Me: ' : 'Peer: '}{String(item.payload)} [{item.status}]</Text>
        )}
      />
      <TextInput value={text} onChangeText={setText} placeholder="Type message..." />
      <Button title="Send" onPress={() => { chat?.sendMessage(text); setText(''); }} />
    </View>
  );
}
```

---

## 4. Testing & Verification Runbook

Always run these commands before submitting PRs:

| Command | Purpose |
| :--- | :--- |
| `yarn lint` | Verify ESLint & Prettier compliance |
| `yarn lint --fix` | Automatically format files to project standard |
| `yarn typecheck` | Run TypeScript compiler type assertions |
| `yarn test --coverage` | Run Jest unit tests and assert line coverage |
| `yarn prepare` | Compile library output to `lib/module` and `lib/typescript` |
| `npm pack --dry-run` | Inspect generated package tarball for published contents |

---

## 5. Troubleshooting & Debugging Guide

### 1. `Invalid peer handshake`
- **Cause**: Duplicate or conflicting `hello` messages sent over WebRTC control channel.
- **Fix**: Verify `helloSent` latch is active and `handleControlMessage` ignores identical replayed public keys.

### 2. `TCP connection refused` or `ETIMEDOUT`
- **Cause**: Host advertised IP is unreachable from the guest device (e.g. host bound to `127.0.0.1` instead of LAN IP).
- **Fix**: Check `getHostOptions` returns the device's actual Wi-Fi IP (`192.168.x.x` or Tailscale IP) using `NetInfo.fetch()`.

### 3. `The lockfile would have been modified by this install`
- **Cause**: `package.json` changed without running `yarn install` to update `yarn.lock` under Yarn Berry.
- **Fix**: Run `yarn install` and commit the updated `yarn.lock`.

### 4. `Missing script: "mkdist"`
- **Cause**: `react-native bundle` outputs to `dist/`, which requires `mkdir -p dist`.
- **Fix**: Ensure `"mkdist": "mkdir -p dist"` is in `example/package.json`.
