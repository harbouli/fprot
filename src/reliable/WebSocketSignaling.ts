import type { PeerIdentity, SignalTransport } from './types';
import { sign } from './identity';

export interface WebSocketSignalingOptions {
  url: string;
  token: string;
  identity: PeerIdentity;
  /** Explicit opt-in for a trusted development LAN. Use wss:// in production. */
  allowInsecureLocalDevelopment?: boolean;
}

/** Reconnecting authenticated transport for server/signaling.mjs. */
export class WebSocketSignaling implements SignalTransport {
  private socket?: WebSocket;
  private timer?: ReturnType<typeof setTimeout>;
  private authTimer?: ReturnType<typeof setTimeout>;
  private handlers?: Parameters<SignalTransport['start']>[0];
  private authenticated = false;
  private retries = 0;

  constructor(private options: WebSocketSignalingOptions) {
    if (
      !options.url.startsWith('wss://') &&
      !(
        options.allowInsecureLocalDevelopment && options.url.startsWith('ws://')
      )
    )
      throw new Error(
        'Signaling requires wss://; explicitly opt into ws:// only on a trusted development LAN'
      );
    if (options.token.length < 32)
      throw new Error('Signaling token must contain at least 32 characters');
  }

  start(handlers: Parameters<SignalTransport['start']>[0]): void {
    this.stop();
    this.handlers = handlers;
    this.connect();
  }

  private connect(): void {
    if (!this.handlers) return;
    const socket = new WebSocket(this.options.url);
    this.socket = socket;
    this.authTimer = setTimeout(() => {
      if (this.socket === socket) socket.close();
    }, 10_000);
    socket.onmessage = (event) => {
      if (this.socket !== socket || typeof event.data !== 'string') return;
      try {
        if (event.data.length > 132 * 1024) throw new Error('Signal too large');
        const value = JSON.parse(event.data);
        if (
          value.type === 'challenge' &&
          !this.authenticated &&
          /^[a-f0-9]{64}$/.test(value.nonce)
        ) {
          socket.send(
            JSON.stringify({
              type: 'auth',
              token: this.options.token,
              publicKey: this.options.identity.publicKey,
              signature: sign(
                `fprot.broker.v1:${value.nonce}`,
                this.options.identity
              ),
            })
          );
        } else if (value.type === 'ready' && !this.authenticated) {
          this.authenticated = true;
          this.retries = 0;
          clearTimeout(this.authTimer);
          this.handlers?.onOnline(true);
        } else if (
          value.type === 'signal' &&
          this.authenticated &&
          typeof value.data === 'string'
        ) {
          this.handlers?.onMessage(value.data);
        }
      } catch {
        socket.close();
      }
    };
    socket.onerror = () => socket.close();
    socket.onclose = () => {
      if (this.socket !== socket) return;
      this.socket = undefined;
      this.authenticated = false;
      clearTimeout(this.authTimer);
      this.handlers?.onOnline(false);
      if (this.handlers)
        this.timer = setTimeout(
          () => this.connect(),
          Math.min(30_000, 1000 * 2 ** Math.min(this.retries++, 5)) *
            (0.75 + Math.random() * 0.5)
        );
    };
  }

  send(message: string): boolean {
    if (!this.authenticated || this.socket?.readyState !== WebSocket.OPEN)
      return false;
    try {
      this.socket.send(JSON.stringify({ type: 'signal', data: message }));
      return true;
    } catch {
      this.socket.close();
      return false;
    }
  }

  stop(): void {
    clearTimeout(this.timer);
    clearTimeout(this.authTimer);
    this.handlers = undefined;
    const socket = this.socket;
    this.socket = undefined;
    this.authenticated = false;
    socket?.close();
  }
}
