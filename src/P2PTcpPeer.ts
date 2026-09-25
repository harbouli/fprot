import { RTCPeerConnection, RTCSessionDescription } from 'react-native-webrtc';

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
  JsonValue,
  P2PMessage,
  P2PTcpPeerOptions,
  PeerEventMap,
  PeerState,
  TcpHostOptions,
  Unsubscribe,
} from './types';

const DEFAULT_ICE_TIMEOUT = 12_000;
const DEFAULT_TCP_TIMEOUT = 10_000;
const DEFAULT_MAX_FRAME = 1024 * 1024;

type Role = 'host' | 'guest';
type TcpServer = ReturnType<typeof TcpSocket.createServer>;
type TcpConnection = ReturnType<typeof TcpSocket.createConnection>;
type ControlChannel = ReturnType<RTCPeerConnection['createDataChannel']>;

interface ControlHello {
  type: 'hello';
  v: 1;
  publicKey: string;
  endpoint?: { host: string; port: number };
}

interface ControlConnect {
  type: 'connect';
}

type ControlMessage = ControlHello | ControlConnect;

interface WirePayload {
  v: 2;
  sender: Role;
  seq: number;
  kind: 'ready' | 'message';
  message?: P2PMessage;
}

/**
 * Negotiates an ephemeral key and reachable endpoint over WebRTC, then moves all
 * application traffic to an authenticated, end-to-end encrypted TCP stream.
 */
export class P2PTcpPeer {
  private readonly options: Required<P2PTcpPeerOptions>;
  private readonly events = new EventBus();
  private peerConnection: RTCPeerConnection | null = null;
  private controlChannel: ControlChannel | null = null;
  private server: TcpServer | null = null;
  private socket: TcpConnection | null = null;
  private keys: SessionKeys | null = null;
  private remotePublicKey: Uint8Array | null = null;
  private endpoint: { host: string; port: number } | null = null;
  private decoder: LineDecoder;
  private role: Role | null = null;
  private txSequence = 0;
  private rxSequence = 0;
  private helloSent = false;
  private connectPending = false;
  private _state: PeerState = 'idle';
  private cancelIce?: () => void;

  constructor(options: P2PTcpPeerOptions = {}) {
    this.options = {
      iceServers: options.iceServers ?? [],
      iceGatheringTimeoutMs:
        options.iceGatheringTimeoutMs ?? DEFAULT_ICE_TIMEOUT,
      tcpConnectTimeoutMs: options.tcpConnectTimeoutMs ?? DEFAULT_TCP_TIMEOUT,
      maxFrameBytes: options.maxFrameBytes ?? DEFAULT_MAX_FRAME,
    };
    if (
      this.options.iceGatheringTimeoutMs <= 0 ||
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

  /** Starts the reachable TCP listener and returns a self-contained WebRTC offer. */
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
      const pc = this.createPeerConnection();
      this.setupControlChannel(
        pc.createDataChannel('p2p-tcp-control', {
          ordered: true,
        })
      );
      await pc.setLocalDescription(await pc.createOffer());
      this.assertActive();
      await this.waitForIceGathering(pc);
      this.assertActive();
      if (!pc.localDescription?.sdp) {
        throw new Error('WebRTC did not produce a local offer');
      }
      this.setState('negotiating');
      return encodeSignal('offer', pc.localDescription.sdp);
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
      const pc = this.createPeerConnection();
      pc.ondatachannel = (event: { channel: ControlChannel }) =>
        this.setupControlChannel(event.channel);
      await pc.setRemoteDescription(
        new RTCSessionDescription({ type: 'offer', sdp: decoded.sdp })
      );
      this.assertActive();
      await pc.setLocalDescription(await pc.createAnswer());
      this.assertActive();
      await this.waitForIceGathering(pc);
      this.assertActive();
      if (!pc.localDescription?.sdp) {
        throw new Error('WebRTC did not produce a local answer');
      }
      this.setState('negotiating');
      return encodeSignal('answer', pc.localDescription.sdp);
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }

  /** Applies the guest's answer. The encrypted TCP connection then opens automatically. */
  async acceptAnswer(answer: string): Promise<void> {
    if (this.role !== 'host' || !this.peerConnection) {
      throw new Error('createOffer must be called before acceptAnswer');
    }
    try {
      const decoded = decodeSignal(answer, 'answer');
      await this.peerConnection.setRemoteDescription(
        new RTCSessionDescription({ type: 'answer', sdp: decoded.sdp })
      );
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
    this.cancelIce?.();
    this.cancelIce = undefined;
    this.controlChannel?.close();
    this.peerConnection?.close();
    this.socket?.destroy();
    if (this.server?.listening) {
      this.server.close();
    }
    this.controlChannel = null;
    this.peerConnection = null;
    this.socket = null;
    this.server = null;
    this.keys?.privateKey.fill(0);
    this.keys = null;
    this.remotePublicKey = null;
    this.helloSent = false;
    this.connectPending = false;
  }

  private assertActive(): void {
    if (this.state === 'closed' || this.state === 'failed')
      throw new Error('Session was cancelled');
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

  private createPeerConnection(): RTCPeerConnection {
    const pc = new RTCPeerConnection({ iceServers: this.options.iceServers });
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed' && this.state !== 'connected') {
        this.fail(new Error('WebRTC handshake failed'));
      }
    };
    this.peerConnection = pc;
    return pc;
  }

  private setupControlChannel(channel: ControlChannel): void {
    if (
      this.controlChannel ||
      this.state === 'closed' ||
      this.state === 'failed'
    ) {
      channel.close();
      return;
    }
    this.controlChannel = channel;
    this.helloSent = false;
    this.connectPending = false;
    channel.onopen = () => this.sendHello();
    channel.onmessage = (event: { data: unknown }) => {
      this.sendHello();
      try {
        this.handleControlMessage(
          JSON.parse(String(event.data)) as ControlMessage
        );
      } catch (error) {
        this.fail(error);
      }
    };
    channel.onerror = () => {
      if (this.state !== 'connected') {
        this.fail(new Error('WebRTC control channel failed'));
      }
    };
    if (channel.readyState === 'open') this.sendHello();
  }

  private sendHello(): void {
    if (
      this.helloSent ||
      !this.controlChannel ||
      this.controlChannel.readyState !== 'open'
    ) {
      return;
    }
    if (!this.keys) {
      this.fail(new Error('Encryption keys were not initialized'));
      return;
    }
    this.helloSent = true;
    const hello: ControlHello = {
      type: 'hello',
      v: 1,
      publicKey: exportPublicKey(this.keys.publicKey),
      ...(this.role === 'host' && this.endpoint
        ? { endpoint: this.endpoint }
        : {}),
    };
    try {
      this.controlChannel.send(JSON.stringify(hello));
    } catch (error) {
      this.fail(error);
    }
  }

  private handleControlMessage(message: ControlMessage): void {
    if (message.type === 'hello') {
      if (message.v !== 1 || typeof message.publicKey !== 'string') {
        throw new Error('Invalid peer handshake');
      }
      const remoteKey = importPublicKey(message.publicKey);
      if (remoteKey.length !== 32)
        throw new Error('Invalid session public key');
      if (this.remotePublicKey) {
        if (
          this.remotePublicKey.length === remoteKey.length &&
          this.remotePublicKey.every((b, i) => b === remoteKey[i])
        ) {
          return;
        }
        throw new Error('Invalid peer handshake');
      }
      this.remotePublicKey = remoteKey;
      if (this.role === 'guest') {
        if (
          !message.endpoint?.host ||
          !Number.isInteger(message.endpoint.port) ||
          message.endpoint.port < 1 ||
          message.endpoint.port > 65_535
        ) {
          throw new Error('Host did not provide a valid TCP endpoint');
        }
        this.endpoint = message.endpoint;
        if (this.connectPending) {
          this.connectPending = false;
          this.connectTcp(this.endpoint);
        }
      } else {
        this.sendHello();
        this.controlChannel?.send(JSON.stringify({ type: 'connect' }));
      }
      return;
    }

    if (message.type === 'connect' && this.role === 'guest') {
      if (!this.remotePublicKey || !this.endpoint) {
        this.connectPending = true;
        return;
      }
      this.connectTcp(this.endpoint);
    }
  }

  private startTcpServer(host: TcpHostOptions): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = TcpSocket.createServer((socket) => {
        if (!this.remotePublicKey || this.socket) {
          socket.destroy();
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
      if (payload.seq !== 1 || this.state === 'connected')
        throw new Error('Unexpected TCP ready frame');
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
    } else throw new Error('Unexpected TCP message');
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
    this.controlChannel?.close();
    this.peerConnection?.close();
    this.controlChannel = null;
    this.peerConnection = null;
  }

  private waitForIceGathering(pc: RTCPeerConnection): Promise<void> {
    if (pc.iceGatheringState === 'complete') {
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      this.cancelIce = () => {
        clearTimeout(timeout);
        pc.onicegatheringstatechange = null;
        reject(new Error('Session was cancelled'));
      };
      const timeout = setTimeout(() => {
        this.cancelIce = undefined;
        pc.onicegatheringstatechange = null;
        reject(new Error('Timed out while gathering WebRTC ICE candidates'));
      }, this.options.iceGatheringTimeoutMs);
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === 'complete') {
          clearTimeout(timeout);
          this.cancelIce = undefined;
          pc.onicegatheringstatechange = null;
          resolve();
        }
      };
    });
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
