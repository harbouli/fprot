export type PeerState =
  | 'idle'
  | 'signaling'
  | 'negotiating'
  | 'tcp-connecting'
  | 'connected'
  | 'closed'
  | 'failed';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface P2PMessage {
  id: string;
  payload: JsonValue;
  sentAt: number;
}

export interface TcpHostOptions {
  /** Address the other device can use to reach this device. */
  advertiseHost: string;
  /** Local address on which the TCP server listens. Defaults to 0.0.0.0. */
  listenHost?: string;
  /** TCP port. Use 0 to let the OS choose one. Defaults to 0. */
  port?: number;
}

export interface IceServer {
  urls: string | string[];
  username?: string;
  credential?: string;
}

export interface SocksProxyOptions {
  /** Proxy host address, e.g. '127.0.0.1' */
  host: string;
  /** Proxy port, e.g. 9050 (Tor) or 5350 (Orbot) */
  port: number;
  /** Optional SOCKS5 username */
  username?: string;
  /** Optional SOCKS5 password */
  password?: string;
}

export interface P2PTcpPeerOptions {
  /** @deprecated WebRTC has been removed from fprot. This option is ignored. */
  iceServers?: IceServer[];
  /** @deprecated WebRTC has been removed from fprot. This option is ignored. */
  iceGatheringTimeoutMs?: number;
  /** Maximum wait when opening the TCP client socket. */
  tcpConnectTimeoutMs?: number;
  /** Maximum encrypted line size accepted from the network. */
  maxFrameBytes?: number;
  /** Optional Tor / SOCKS5 proxy configuration for outbound TCP connections. */
  proxy?: SocksProxyOptions;
  /**
   * If true, suppresses clearnet fallback and enforces Tor-only routing.
   */
  torMode?: boolean;
}

export interface PeerEventMap {
  state: PeerState;
  message: P2PMessage;
  error: Error;
  close: undefined;
}

export type Unsubscribe = () => void;
