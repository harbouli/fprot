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

export interface P2PTcpPeerOptions {
  iceServers?: IceServer[];
  /** Maximum wait for non-trickle ICE candidate gathering. */
  iceGatheringTimeoutMs?: number;
  /** Maximum wait when opening the TCP client socket. */
  tcpConnectTimeoutMs?: number;
  /** Maximum encrypted line size accepted from the network. */
  maxFrameBytes?: number;
}

export interface PeerEventMap {
  state: PeerState;
  message: P2PMessage;
  error: Error;
  close: undefined;
}

export type Unsubscribe = () => void;
