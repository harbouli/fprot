import { EventBus } from './internal/EventBus';
import { LineDecoder } from './internal/LineDecoder';
import { TcpSocket } from './internal/tcp';
import {
  createSessionKeys,
  decryptJson,
  encryptJson,
  exportPublicKey,
  importPublicKey,
  randomId,
  type EncryptedFrame,
  type SessionKeys,
} from './internal/crypto';
import { decodeSignal, encodeSignal } from './internal/signaling';
import type {
  IceServer,
  JsonValue,
  P2PMessage,
  P2PTcpPeerOptions,
  PeerEventMap,
  PeerState,
  SocksProxyOptions,
  TcpHostOptions,
  Unsubscribe,
} from './types';

const DEFAULT_TCP_TIMEOUT = 10_000;
const DEFAULT_MAX_FRAME = 1024 * 1024;

type Role = 'host' | 'guest';
type TcpServer = ReturnType<typeof TcpSocket.createServer>;
type TcpConnection = ReturnType<typeof TcpSocket.createConnection>;

interface PeerOfferPayload {
  v: 1;
  publicKey: string;
  endpoint: { host: string; port: number };
}

interface PeerAnswerPayload {
  v: 1;
  publicKey: string;
}

interface WirePayload {
  v: 2;
  sender: Role;
  seq: number;
  kind: 'ready' | 'message';
  message?: P2PMessage;
}

/**
 * Negotiates an ephemeral public key and reachable endpoint directly or through signaling,
 * then establishes an authenticated, end-to-end encrypted TCP stream with optional Tor routing.
 */
export class P2PTcpPeer {
  private readonly options: Required<
    Omit<
      P2PTcpPeerOptions,
      'proxy' | 'torMode' | 'iceServers' | 'iceGatheringTimeoutMs'
    >
  > & {
    proxy?: SocksProxyOptions;
    torMode: boolean;
    iceServers?: IceServer[];
    iceGatheringTimeoutMs?: number;
  };
  private readonly events = new EventBus();
  private server: TcpServer | null = null;
  private socket: TcpConnection | null = null;
  private pendingIncomingSocket: TcpConnection | null = null;
  private keys: SessionKeys | null = null;
  private remotePublicKey: Uint8Array | null = null;
  private endpoint: { host: string; port: number } | null = null;
  private decoder: LineDecoder;
  private role: Role | null = null;
  private txSequence = 0;
  private rxSequence = 0;
  private _state: PeerState = 'idle';

  constructor(options: P2PTcpPeerOptions = {}) {
    this.options = {
      iceServers: options.torMode ? [] : (options.iceServers ?? []),
      iceGatheringTimeoutMs: options.iceGatheringTimeoutMs,
      tcpConnectTimeoutMs: options.tcpConnectTimeoutMs ?? DEFAULT_TCP_TIMEOUT,
      maxFrameBytes: options.maxFrameBytes ?? DEFAULT_MAX_FRAME,
      proxy: options.proxy,
      torMode: options.torMode ?? false,
    };
    if (
      this.options.tcpConnectTimeoutMs <= 0 ||
      this.options.maxFrameBytes < 256
    ) {
      throw new Error(
        'Timeouts must be positive and maxFrameBytes must be at least 256'
      );
    }
    this.decoder = new LineDecoder(this.options.maxFrameBytes);
  }

  get state(): PeerState {
    return this._state;
  }

  on<K extends keyof PeerEventMap>(
    event: K,
    listener: (value: PeerEventMap[K]) => void
  ): Unsubscribe {
    return this.events.on(event, listener);
  }

  /** Starts the reachable TCP listener and returns a self-contained offer signal. */
  async createOffer(host: TcpHostOptions): Promise<string> {
    this.assertIdle();
    if (!host.advertiseHost.trim()) {
      throw new Error(
        'advertiseHost must be a reachable IP address or hostname'
      );
    }
    if (
      host.port !== undefined &&
      (!Number.isInteger(host.port) || host.port < 0 || host.port > 65_535)
    ) {
      throw new Error('port must be an integer between 0 and 65535');
    }
    this.role = 'host';
    this.setState('signaling');

    try {
      await this.ensureKeys();
      this.assertActive();
      const port = await this.startTcpServer(host);
      this.assertActive();
      this.endpoint = { host: host.advertiseHost, port };
      const payload: PeerOfferPayload = {
        v: 1,
        publicKey: exportPublicKey(this.keys!.publicKey),
        endpoint: this.endpoint,
      };
      this.setState('negotiating');
      return encodeSignal('offer', JSON.stringify(payload));
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }

  /** Accepts an offer and returns the answer to deliver to the host. */
  async acceptOffer(offer: string): Promise<string> {
    this.assertIdle();
    this.role = 'guest';
    this.setState('signaling');

    try {
      await this.ensureKeys();
      this.assertActive();
      const decoded = decodeSignal(offer, 'offer');
      let payload: PeerOfferPayload;
      try {
        payload = JSON.parse(decoded.sdp);
      } catch {
        throw new Error('Invalid offer payload');
      }
      if (
        !payload ||
        payload.v !== 1 ||
        typeof payload.publicKey !== 'string' ||
        !payload.endpoint
      ) {
        throw new Error('Invalid offer payload');
      }
      const remoteKey = importPublicKey(payload.publicKey);
      if (remoteKey.length !== 32) {
        throw new Error('Invalid session public key');
      }
      if (
        !payload.endpoint.host ||
        !Number.isInteger(payload.endpoint.port) ||
        payload.endpoint.port < 1 ||
        payload.endpoint.port > 65_535
      ) {
        throw new Error('Host did not provide a valid TCP endpoint');
      }
      this.remotePublicKey = remoteKey;
      this.endpoint = payload.endpoint;

      // Connect to host's TCP endpoint (clearnet direct or through Tor proxy)
      this.connectTcp(this.endpoint);

      const answerPayload: PeerAnswerPayload = {
        v: 1,
        publicKey: exportPublicKey(this.keys!.publicKey),
      };
      this.setState('negotiating');
      return encodeSignal('answer', JSON.stringify(answerPayload));
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }

  /** Applies the guest's answer. Attaches any pending incoming TCP socket. */
  async acceptAnswer(answer: string): Promise<void> {
    if (this.role !== 'host') {
      throw new Error('createOffer must be called before acceptAnswer');
    }
    try {
      const decoded = decodeSignal(answer, 'answer');
      let payload: PeerAnswerPayload;
      try {
        payload = JSON.parse(decoded.sdp);
      } catch {
        throw new Error('Invalid answer payload');
      }
      if (
        !payload ||
        payload.v !== 1 ||
        typeof payload.publicKey !== 'string'
      ) {
        throw new Error('Invalid answer payload');
      }
      const remoteKey = importPublicKey(payload.publicKey);
      if (remoteKey.length !== 32) {
        throw new Error('Invalid session public key');
      }
      this.remotePublicKey = remoteKey;

      if (this.pendingIncomingSocket) {
        const socket = this.pendingIncomingSocket;
        this.pendingIncomingSocket = null;
        this.attachSocket(socket);
      }
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }

  /** Sends one JSON-compatible value through the encrypted TCP stream. */
  sendMessage(payload: JsonValue): string {
    if (this.state !== 'connected' || !this.socket) {
      throw new Error('The peer is not connected');
    }
    const message: P2PMessage = {
      id: randomId(),
      payload,
      sentAt: Date.now(),
    };
    this.sendWire({ kind: 'message', message });
    return message.id;
  }

  close(): void {
    if (this.state === 'closed') {
      return;
    }
    this.setState('closed');
    this.dispose();
    this.events.emit('close', undefined);
  }

  private dispose(): void {
    this.pendingIncomingSocket?.destroy();
    this.pendingIncomingSocket = null;
    this.socket?.destroy();
    this.socket = null;
    if (this.server?.listening) {
      this.server.close();
    }
    this.server = null;
    this.keys?.privateKey.fill(0);
    this.keys = null;
    this.remotePublicKey = null;
  }

  private assertActive(): void {
    if (this.state === 'closed' || this.state === 'failed') {
      throw new Error('Session was cancelled');
    }
  }

  private assertIdle(): void {
    if (this.state !== 'idle') {
      throw new Error('A P2PTcpPeer instance can establish only one session');
    }
  }

  private async ensureKeys(): Promise<void> {
    const keys = await createSessionKeys();
    if (this.state === 'closed' || this.state === 'failed') {
      keys.privateKey.fill(0);
      throw new Error('Session was cancelled');
    }
    this.keys = keys;
  }

  private startTcpServer(host: TcpHostOptions): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = TcpSocket.createServer((socket) => {
        if (this.socket) {
          socket.destroy();
          return;
        }
        if (!this.remotePublicKey) {
          if (this.pendingIncomingSocket) {
            this.pendingIncomingSocket.destroy();
          }
          this.pendingIncomingSocket = socket;
          socket.once('close', () => {
            if (this.pendingIncomingSocket === socket) {
              this.pendingIncomingSocket = null;
            }
          });
          socket.once('error', () => {
            if (this.pendingIncomingSocket === socket) {
              this.pendingIncomingSocket = null;
            }
          });
          return;
        }
        this.attachSocket(socket);
      });
      this.server = server;
      server.once('error', reject);
      server.listen(
        {
          port: host.port ?? 0,
          host: host.listenHost ?? '0.0.0.0',
          reuseAddress: true,
        },
        () => {
          if (this.state === 'closed' || this.state === 'failed') {
            server.close();
            reject(new Error('Session was cancelled'));
            return;
          }
          server.removeListener('error', reject);
          const address = server.address();
          if (!address) {
            reject(new Error('TCP server did not report a listening address'));
            return;
          }
          server.on('error', (error) => this.fail(error));
          resolve(address.port);
        }
      );
    });
  }

  private connectTcp(endpoint: { host: string; port: number }): void {
    if (this.socket) {
      return;
    }
    this.setState('tcp-connecting');
    const socket = TcpSocket.createConnection(
      {
        host: endpoint.host,
        port: endpoint.port,
        connectTimeout: this.options.tcpConnectTimeoutMs,
        proxy: this.options.proxy,
      },
      () => {
        if (this.state === 'closed' || this.state === 'failed') {
          socket.destroy();
          return;
        }
        this.attachSocket(socket);
        try {
          this.sendWire({ kind: 'ready' });
        } catch (error) {
          this.fail(error);
        }
      }
    );
    this.socket = socket;
    socket.once('error', (error) => this.fail(error));
  }

  private attachSocket(socket: TcpConnection): void {
    this.socket = socket;
    this.decoder = new LineDecoder(this.options.maxFrameBytes);
    socket.setEncoding('utf8');
    socket.setNoDelay(true);
    socket.setKeepAlive(true);
    socket.on('data', (chunk: string | Uint8Array) => {
      try {
        for (const line of this.decoder.push(String(chunk))) {
          this.handleEncryptedLine(line);
        }
      } catch (error) {
        this.fail(error);
      }
    });
    socket.on('error', (error: Error) => this.fail(error));
    socket.on('close', () => {
      if (this.state !== 'closed' && this.state !== 'failed') {
        this.close();
      }
    });
    socket.on('end', () => this.close());
  }

  private sendWire(value: Omit<WirePayload, 'v' | 'seq' | 'sender'>): void {
    if (!this.socket || !this.keys || !this.remotePublicKey) {
      throw new Error('Encrypted TCP session is not ready');
    }
    const payload: WirePayload = {
      ...value,
      v: 2,
      sender: this.role!,
      seq: this.txSequence + 1,
    };
    const frame = encryptJson(
      payload,
      this.remotePublicKey,
      this.keys.privateKey
    );
    const line = `${JSON.stringify(frame)}\n`;
    if (line.length > this.options.maxFrameBytes) {
      throw new Error('Message exceeds the configured frame size limit');
    }
    ++this.txSequence;
    try {
      this.socket.write(line, 'utf8', (error) => {
        if (error) this.fail(error);
      });
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }

  private handleEncryptedLine(line: string): void {
    if (!this.keys || !this.remotePublicKey) {
      throw new Error('Received TCP data before key exchange completed');
    }
    const frame = JSON.parse(line) as EncryptedFrame;
    const payload = decryptJson<WirePayload>(
      frame,
      this.remotePublicKey,
      this.keys.privateKey
    );
    if (
      payload.v !== 2 ||
      payload.sender !== (this.role === 'host' ? 'guest' : 'host') ||
      payload.seq !== this.rxSequence + 1
    ) {
      throw new Error('Rejected an invalid or replayed encrypted frame');
    }
    this.rxSequence = payload.seq;

    if (payload.kind === 'ready') {
      if (payload.seq !== 1 || this.state === 'connected') {
        throw new Error('Unexpected TCP ready frame');
      }
      if (this.role === 'host') {
        this.sendWire({ kind: 'ready' });
      }
      this.markConnected();
      return;
    }
    if (
      this.state === 'connected' &&
      payload.kind === 'message' &&
      payload.message
    ) {
      this.events.emit('message', payload.message);
    } else {
      throw new Error('Unexpected TCP message');
    }
  }

  private markConnected(): void {
    if (this.state === 'connected') {
      return;
    }
    this.setState('connected');
    if (this.server?.listening) {
      this.server.close();
    }
    this.server = null;
    if (this.pendingIncomingSocket) {
      this.pendingIncomingSocket.destroy();
      this.pendingIncomingSocket = null;
    }
  }

  private setState(state: PeerState): void {
    this._state = state;
    this.events.emit('state', state);
  }

  private fail(cause: unknown): void {
    if (this.state === 'failed' || this.state === 'closed') {
      return;
    }
    const error = cause instanceof Error ? cause : new Error(String(cause));
    this.setState('failed');
    this.dispose();
    this.events.emit('error', error);
  }
}
