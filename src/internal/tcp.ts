import { NativeEventEmitter, NativeModules } from 'react-native';

export interface TcpListenOptions {
  port?: number;
  host?: string;
  reuseAddress?: boolean;
}

export interface TcpConnectOptions {
  host: string;
  port: number;
  connectTimeout?: number;
}

export interface TcpSocketConnection {
  setEncoding(encoding: 'utf8'): void;
  setNoDelay(noDelay: boolean): void;
  setKeepAlive(enable: boolean): void;
  on(event: 'data', listener: (chunk: string | Uint8Array) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  on(event: 'close' | 'end', listener: () => void): this;
  once(event: 'error', listener: (error: Error) => void): this;
  write(
    data: string,
    encoding: 'utf8',
    callback?: (error?: Error) => void
  ): void;
  destroy(): void;
}

export interface TcpSocketServer {
  readonly listening: boolean;
  listen(options: TcpListenOptions, listeningListener?: () => void): this;
  address(): { port: number } | null;
  close(): void;
  on(event: 'error', listener: (error: Error) => void): this;
  once(event: 'error', listener: (error: Error) => void): this;
  removeListener(event: 'error', listener: (error: Error) => void): this;
}

interface FprotNativeTcpSpec {
  tcpServerListen(
    serverId: number,
    host: string,
    port: number
  ): Promise<number>;
  tcpServerClose(serverId: number): Promise<void>;
  tcpConnect(
    socketId: number,
    host: string,
    port: number,
    timeoutMs: number
  ): Promise<void>;
  tcpWrite(socketId: number, data: string): Promise<void>;
  tcpDestroy(socketId: number): Promise<void>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

interface TcpNativeEvent {
  type: 'connection' | 'data' | 'error' | 'close';
  serverId?: number;
  socketId: number;
  data?: string;
  error?: string;
}

let nextClientSocketId = 1;
let nextServerId = 1;
const activeSockets = new Map<number, NativeTcpSocket>();
const activeServers = new Map<number, NativeTcpServer>();
let eventSubscriptionInitialized = false;

function getNativeTcp(): FprotNativeTcpSpec | null {
  const mod = (NativeModules as { FprotNative?: FprotNativeTcpSpec })
    ?.FprotNative;
  if (mod && typeof mod.tcpServerListen === 'function') {
    if (!eventSubscriptionInitialized) {
      eventSubscriptionInitialized = true;
      const emitter = new NativeEventEmitter(mod as never);
      emitter.addListener('fprot_tcp_event', (rawEvent: unknown) => {
        const event = rawEvent as TcpNativeEvent;
        if (event.type === 'connection' && event.serverId !== undefined) {
          const server = activeServers.get(event.serverId);
          server?.handleConnection(event.socketId);
          return;
        }
        const socket = activeSockets.get(event.socketId);
        if (!socket) return;
        if (event.type === 'data' && typeof event.data === 'string') {
          socket.handleData(event.data);
        } else if (event.type === 'error') {
          socket.handleError(new Error(event.error ?? 'TCP socket error'));
        } else if (event.type === 'close') {
          socket.handleClose();
        }
      });
    }
    return mod;
  }
  return null;
}

class NativeTcpSocket implements TcpSocketConnection {
  private dataListeners = new Set<(chunk: string | Uint8Array) => void>();
  private errorListeners = new Set<(error: Error) => void>();
  private closeListeners = new Set<() => void>();
  private endListeners = new Set<() => void>();
  private readyForData = false;
  private bufferedData: string[] = [];
  private destroyed = false;

  constructor(
    public readonly socketId: number,
    private readonly native: FprotNativeTcpSpec,
    initiallyReady: boolean
  ) {
    activeSockets.set(socketId, this);
    this.readyForData = initiallyReady;
  }

  markReadyForData(): void {
    this.readyForData = true;
    if (this.bufferedData.length > 0) {
      const chunks = this.bufferedData.splice(0);
      for (const chunk of chunks) {
        this.emitData(chunk);
      }
    }
  }

  setEncoding(_encoding: 'utf8'): void {}
  setNoDelay(_noDelay: boolean): void {}
  setKeepAlive(_enable: boolean): void {}

  on(event: 'data', listener: (chunk: string | Uint8Array) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  on(event: 'close' | 'end', listener: () => void): this;
  on(
    event: 'data' | 'error' | 'close' | 'end',
    listener:
      | ((chunk: string | Uint8Array) => void)
      | ((error: Error) => void)
      | (() => void)
  ): this {
    if (event === 'data') {
      this.dataListeners.add(listener as (chunk: string | Uint8Array) => void);
    } else if (event === 'error') {
      this.errorListeners.add(listener as (error: Error) => void);
    } else if (event === 'close') {
      this.closeListeners.add(listener as () => void);
    } else if (event === 'end') {
      this.endListeners.add(listener as () => void);
    }
    return this;
  }

  once(_event: 'error', listener: (error: Error) => void): this {
    const wrapper = (err: Error) => {
      this.errorListeners.delete(wrapper);
      listener(err);
    };
    this.errorListeners.add(wrapper);
    return this;
  }

  write(
    data: string,
    _encoding: 'utf8',
    callback?: (error?: Error) => void
  ): void {
    if (this.destroyed) {
      callback?.(new Error('Socket is closed'));
      return;
    }
    this.native
      .tcpWrite(this.socketId, data)
      .then(() => callback?.())
      .catch((err) => {
        const error = err instanceof Error ? err : new Error(String(err));
        callback?.(error);
      });
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    activeSockets.delete(this.socketId);
    this.native.tcpDestroy(this.socketId).catch(() => {});
  }

  handleData(chunk: string): void {
    if (this.destroyed) return;
    if (!this.readyForData) {
      this.bufferedData.push(chunk);
      return;
    }
    this.emitData(chunk);
  }

  private emitData(chunk: string): void {
    for (const listener of [...this.dataListeners]) {
      listener(chunk);
    }
  }

  handleError(error: Error): void {
    if (this.destroyed) return;
    for (const listener of [...this.errorListeners]) {
      listener(error);
    }
  }

  handleClose(): void {
    activeSockets.delete(this.socketId);
    if (this.destroyed) return;
    this.destroyed = true;
    for (const listener of [...this.endListeners]) {
      listener();
    }
    for (const listener of [...this.closeListeners]) {
      listener();
    }
  }
}

class NativeTcpServer implements TcpSocketServer {
  private readonly serverId = nextServerId++;
  private errorListeners = new Set<(error: Error) => void>();
  private boundPort: number | null = null;
  public listening = false;

  constructor(
    private readonly native: FprotNativeTcpSpec,
    private readonly connectionListener: (socket: TcpSocketConnection) => void
  ) {}

  listen(options: TcpListenOptions, listeningListener?: () => void): this {
    activeServers.set(this.serverId, this);
    const host = options.host ?? '0.0.0.0';
    const port = options.port ?? 0;
    this.native
      .tcpServerListen(this.serverId, host, port)
      .then((assignedPort) => {
        if (!activeServers.has(this.serverId)) {
          this.native.tcpServerClose(this.serverId).catch(() => {});
          return;
        }
        this.boundPort = assignedPort;
        this.listening = true;
        listeningListener?.();
      })
      .catch((err) => {
        activeServers.delete(this.serverId);
        const error = err instanceof Error ? err : new Error(String(err));
        for (const listener of [...this.errorListeners]) {
          listener(error);
        }
      });
    return this;
  }

  address(): { port: number } | null {
    return this.boundPort !== null ? { port: this.boundPort } : null;
  }

  close(): void {
    this.listening = false;
    activeServers.delete(this.serverId);
    this.native.tcpServerClose(this.serverId).catch(() => {});
  }

  on(event: 'error', listener: (error: Error) => void): this {
    if (event === 'error') {
      this.errorListeners.add(listener);
    }
    return this;
  }

  once(event: 'error', listener: (error: Error) => void): this {
    if (event === 'error') {
      const wrapper = (err: Error) => {
        this.errorListeners.delete(wrapper);
        listener(err);
      };
      this.errorListeners.add(wrapper);
    }
    return this;
  }

  removeListener(event: 'error', listener: (error: Error) => void): this {
    if (event === 'error') {
      this.errorListeners.delete(listener);
    }
    return this;
  }

  handleConnection(socketId: number): void {
    if (!this.listening) {
      this.native.tcpDestroy(socketId).catch(() => {});
      return;
    }
    const socket = new NativeTcpSocket(socketId, this.native, false);
    this.connectionListener(socket);
    socket.markReadyForData();
  }
}

function getNodeNet(): typeof import('node:net') {
  const req = module.require.bind(module) as (
    id: string
  ) => typeof import('node:net');
  return req('node:net');
}

export const TcpSocket = {
  createServer(
    connectionListener: (socket: TcpSocketConnection) => void
  ): TcpSocketServer {
    const native = getNativeTcp();
    if (native) {
      return new NativeTcpServer(native, connectionListener);
    }
    const net = getNodeNet();
    return net.createServer((socket) =>
      connectionListener(socket as unknown as TcpSocketConnection)
    ) as unknown as TcpSocketServer;
  },

  createConnection(
    options: TcpConnectOptions,
    connectListener?: () => void
  ): TcpSocketConnection {
    const native = getNativeTcp();
    if (native) {
      const socketId = nextClientSocketId++;
      const socket = new NativeTcpSocket(socketId, native, false);
      const timeoutMs = options.connectTimeout ?? 10_000;
      native
        .tcpConnect(socketId, options.host, options.port, timeoutMs)
        .then(() => {
          connectListener?.();
          socket.markReadyForData();
        })
        .catch((err) => {
          const error = err instanceof Error ? err : new Error(String(err));
          socket.handleError(error);
          socket.destroy();
        });
      return socket;
    }
    const net = getNodeNet();
    const socket = net.createConnection(
      {
        host: options.host,
        port: options.port,
      },
      () => {
        socket.setTimeout(0);
        connectListener?.();
      }
    );
    if (options.connectTimeout && options.connectTimeout > 0) {
      socket.setTimeout(options.connectTimeout, () => {
        socket.destroy(new Error('TCP connection timed out'));
      });
    }
    return socket as unknown as TcpSocketConnection;
  },
};
