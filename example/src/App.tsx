import { useEffect, useRef, useState } from 'react';
import {
  AppState,
  Button,
  ScrollView,
  Share,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  View,
} from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import NetInfo from '@react-native-community/netinfo';
import {
  ReliableConversation,
  WebSocketSignaling,
  type ChatMessage,
  type ConversationState,
} from 'fprot';
import { loadDevice, secureStorage } from './storage';

interface Settings {
  url: string;
  token: string;
  remote: string;
  conversation: string;
  host: string;
  role: 'host' | 'guest';
  insecure: boolean;
}
const defaults: Settings = {
  url: 'ws://192.168.1.10:8787',
  token: '',
  remote: '',
  conversation: 'our-chat',
  host: '',
  role: 'host',
  insecure: false,
};

export default function App() {
  const session = useRef<ReliableConversation | null>(null);
  const cleanup = useRef<() => void>(() => {});
  const lifecycle = useRef(0);
  const [settings, setSettings] = useState(defaults);
  const [publicKey, setPublicKey] = useState('');
  const [state, setState] = useState<ConversationState>('stopped');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const [paused, setPaused] = useState(false);
  const [busy, setBusy] = useState(false);
  const pausedRef = useRef(false);

  useEffect(() => {
    let mounted = true;
    void (async () => {
      const device = await loadDevice();
      const saved = await secureStorage.getItem('fprot.example.settings.v1');
      if (!mounted) return;
      setPublicKey(device.identity.publicKey);
      if (saved) {
        const config: Settings = JSON.parse(saved);
        setSettings(config);
        await connect(config);
      }
    })().catch((value) => {
      if (mounted) setError(String(value));
    });
    return () => {
      mounted = false;
      // This is a cancellation counter, not a DOM/native view ref.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      ++lifecycle.current;
      cleanup.current();
      session.current?.stop();
    };
    // Setup is restored once on mount; subsequent changes use the Connect button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function connect(config = settings) {
    const epoch = ++lifecycle.current;
    setBusy(true);
    setError('');
    cleanup.current();
    session.current?.stop();
    session.current = null;
    try {
      const { identity, storage } = await loadDevice();
      if (epoch !== lifecycle.current) return;
      const chat = new ReliableConversation({
        identity,
        remotePublicKey: config.remote.trim(),
        conversationId: config.conversation.trim(),
        role: config.role,
        storage,
        signaling: new WebSocketSignaling({
          url: config.url.trim(),
          token: config.token.trim(),
          identity,
          allowInsecureLocalDevelopment: config.insecure,
        }),
        getHostOptions: async () => {
          const network = await NetInfo.fetch();
          const address =
            config.host.trim() ||
            (network.type === 'wifi' ? network.details.ipAddress : undefined);
          if (!address)
            throw new Error(
              'Enter a reachable host address, or connect the host to Wi-Fi'
            );
          return { advertiseHost: address };
        },
      });
      session.current = chat;
      const unsubs = [
        chat.on('state', setState),
        chat.on('messages', setMessages),
        chat.on('error', (value) => setError(value.message)),
      ];
      await chat.start();
      if (epoch !== lifecycle.current) {
        chat.stop();
        unsubs.forEach((off) => off());
        return;
      }
      await secureStorage.setItem(
        'fprot.example.settings.v1',
        JSON.stringify(config)
      );
      let connected = true;
      let signature = '';
      const updateAvailability = () =>
        chat.setAvailable(
          connected && AppState.currentState === 'active' && !pausedRef.current
        );
      const networkOff = NetInfo.addEventListener((network) => {
        connected = network.isConnected === true;
        const next = `${network.type}:${network.type === 'wifi' ? network.details.ipAddress : ''}`;
        const changed = signature !== '' && next !== signature;
        signature = next;
        updateAvailability();
        if (
          changed &&
          connected &&
          AppState.currentState === 'active' &&
          !pausedRef.current
        )
          chat.reconnect();
      });
      const appListener = AppState.addEventListener(
        'change',
        updateAvailability
      );
      updateAvailability();
      cleanup.current = () => {
        networkOff();
        appListener.remove();
        unsubs.forEach((off) => off());
      };
    } catch (value) {
      if (epoch === lifecycle.current) {
        session.current?.stop();
        session.current = null;
        setError(String(value));
      }
    } finally {
      if (epoch === lifecycle.current) setBusy(false);
    }
  }

  function field(key: keyof Settings, value: string) {
    setSettings((old) => ({ ...old, [key]: value }));
  }
  async function send() {
    if (!draft.trim() || !session.current) return;
    const text = draft.trim();
    try {
      await session.current.sendMessage(text);
      setDraft('');
    } catch (value) {
      setError(String(value));
    }
  }

  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.safe}>
        <ScrollView
          contentContainerStyle={styles.container}
          keyboardShouldPersistTaps="handled"
        >
          <Text style={styles.title}>fprot</Text>
          <Text style={styles.subtitle}>
            Your conversation survives reconnects.
          </Text>
          <Text style={styles.label}>
            Your public identity — share once with your friend
          </Text>
          <Text selectable style={styles.key}>
            {publicKey || 'Loading secure identity…'}
          </Text>
          <Button
            title="Share my identity"
            disabled={!publicKey}
            onPress={() => {
              void Share.share({ message: publicKey }).catch((value) =>
                setError(String(value))
              );
            }}
          />
          <Text style={styles.hint}>
            Verify your friend's public key through a trusted channel. It stays
            pinned for this conversation.
          </Text>
          {(
            [
              ['remote', "Friend's public identity"],
              ['conversation', 'Shared conversation name'],
              ['url', 'Signaling server URL'],
              ['token', 'Signaling access token'],
              ['host', 'Host address (blank = current Wi-Fi address)'],
            ] as const
          ).map(([key, label]) => (
            <View key={key}>
              <Text style={styles.label}>{label}</Text>
              <TextInput
                style={styles.input}
                autoCapitalize="none"
                autoCorrect={false}
                secureTextEntry={key === 'token'}
                value={settings[key]}
                onChangeText={(value) => field(key, value)}
              />
            </View>
          ))}
          <View style={styles.row}>
            <Button
              title={settings.role === 'host' ? '✓ Host' : 'Host'}
              onPress={() => setSettings((old) => ({ ...old, role: 'host' }))}
            />
            <Button
              title={settings.role === 'guest' ? '✓ Guest' : 'Guest'}
              onPress={() => setSettings((old) => ({ ...old, role: 'guest' }))}
            />
          </View>
          <Text style={styles.hint}>
            Choose one host and one guest. Both phones need the same server,
            token, and conversation name.
          </Text>
          <View style={styles.row}>
            <Text style={styles.hint}>
              Allow ws:// on trusted development LAN
            </Text>
            <Switch
              value={settings.insecure}
              onValueChange={(insecure) =>
                setSettings((old) => ({ ...old, insecure }))
              }
            />
          </View>
          <Button
            title={busy ? 'Opening conversation…' : 'Save pairing & connect'}
            disabled={busy || !publicKey}
            onPress={() => {
              void connect();
            }}
          />
          <Text style={styles.status}>
            {state} ·{' '}
            {messages.filter((message) => message.status === 'pending').length}{' '}
            pending
          </Text>
          <Button
            title={
              paused ? 'Resume connection' : 'Pause connection (test offline)'
            }
            disabled={!session.current}
            onPress={() => {
              pausedRef.current = !pausedRef.current;
              setPaused(pausedRef.current);
              session.current?.setAvailable(!pausedRef.current);
            }}
          />
          {messages.map((message) => (
            <View
              key={`${message.direction}:${message.id}`}
              style={styles.message}
            >
              <Text style={styles.messageText}>
                {typeof message.payload === 'string'
                  ? message.payload
                  : JSON.stringify(message.payload)}
              </Text>
              <Text style={styles.hint}>
                {message.direction === 'outgoing'
                  ? `You · ${message.status}`
                  : 'Friend · saved'}
              </Text>
            </View>
          ))}
          <TextInput
            style={styles.input}
            placeholder="Write a message, even while offline"
            value={draft}
            onChangeText={setDraft}
          />
          <Button
            title="Send / queue"
            disabled={!session.current || busy || !draft.trim()}
            onPress={() => {
              void send();
            }}
          />
          {error ? <Text style={styles.error}>{error}</Text> : null}
        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#f4f7fb' },
  container: { padding: 20, gap: 12 },
  title: { fontSize: 30, fontWeight: '700', color: '#13213c' },
  subtitle: { color: '#475467' },
  label: { color: '#344054', fontWeight: '600', marginBottom: 4 },
  key: { color: '#13213c', backgroundColor: '#e8eef8', padding: 10 },
  input: {
    backgroundColor: '#fff',
    borderColor: '#cbd5e1',
    borderRadius: 8,
    borderWidth: 1,
    color: '#101828',
    minHeight: 44,
    padding: 10,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 8,
  },
  status: { fontSize: 17, fontWeight: '600', color: '#315b9d' },
  hint: { color: '#475467', fontSize: 12, flexShrink: 1 },
  message: {
    backgroundColor: '#dbeafe',
    borderRadius: 10,
    padding: 12,
    gap: 4,
  },
  messageText: { color: '#172554' },
  error: { color: '#b42318' },
});
