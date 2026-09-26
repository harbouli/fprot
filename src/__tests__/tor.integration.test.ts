/** @jest-environment node */
import net from 'node:net';
import { afterEach, describe, expect, it } from '@jest/globals';
import { P2PTcpPeer } from '../P2PTcpPeer';
import { TcpSocket } from '../internal/tcp';
import { ReliableConversation } from '../reliable/ReliableConversation';
import type { KeyValueStorage, SignalTransport } from '../reliable/types';
import {
  createEncryptedStorage,
  loadOrCreateIdentity,
} from '../reliable/identity';

interface Socks5Proxy {
  server: net.Server;
  port: number;
  connectionsCount: number;
  lastRequestedHost: string | null;
  lastRequestedPort: number | null;
  close: () => Promise<void>;
}

function createTrackedServer(onConnection: (sock: net.Socket) => void): {
  server: net.Server;
  listen: () => Promise<number>;
  close: () => Promise<void>;
} {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((sock) => {
    sockets.add(sock);
    sock.on('close', () => sockets.delete(sock));
    onConnection(sock);
  });
  return {
    server,
    listen: () =>
      new Promise<number>((resolve) => {
        server.listen(0, '127.0.0.1', () => {
          resolve((server.address() as { port: number }).port);
        });
      }),
    close: () => {
      for (const s of sockets) s.destroy();
      return new Promise<void>((res) => server.close(() => res()));
    },
  };
}

function createMockSocks5Proxy(
  domainRoutingMap: Record<string, { host: string; port: number }> = {}
): Promise<Socks5Proxy> {
  return new Promise((resolve, reject) => {
    let connectionsCount = 0;
    let lastRequestedHost: string | null = null;
    let lastRequestedPort: number | null = null;
    const allSockets = new Set<net.Socket>();

    const server = net.createServer((clientSocket) => {
      connectionsCount++;
      allSockets.add(clientSocket);
      clientSocket.on('close', () => allSockets.delete(clientSocket));
      let stage = 0;
      let targetSocket: net.Socket | null = null;

      const onData = (data: Buffer) => {
        if (stage === 0) {
          if (data.length < 2 || data[0] !== 0x05) {
            clientSocket.destroy();
            return;
          }
          clientSocket.write(Buffer.from([0x05, 0x00]));
          stage = 1;
          return;
        }

        if (stage === 1) {
          if (data.length < 4 || data[0] !== 0x05 || data[1] !== 0x01) {
            clientSocket.destroy();
            return;
          }
          const atyp = data[3];
          let targetHost = '';
          let targetPort = 0;
          let offset = 4;

          if (atyp === 0x01) {
            targetHost = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
            offset += 4;
          } else if (atyp === 0x03) {
            const len = data[offset]!;
            offset += 1;
            targetHost = data.subarray(offset, offset + len).toString('utf8');
            offset += len;
          }
          targetPort = data.readUInt16BE(offset);

          lastRequestedHost = targetHost;
          lastRequestedPort = targetPort;

          let routeHost = targetHost;
          let routePort = targetPort;
          if (domainRoutingMap[targetHost]) {
            routeHost = domainRoutingMap[targetHost]!.host;
            routePort = domainRoutingMap[targetHost]!.port;
          }

          targetSocket = net.createConnection(
            { host: routeHost, port: routePort },
            () => {
              clientSocket.write(
                Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
              );
              stage = 2;
              clientSocket.removeListener('data', onData);
              clientSocket.pipe(targetSocket!);
              targetSocket!.pipe(clientSocket);
            }
          );
          allSockets.add(targetSocket);
          targetSocket.on('close', () => {
            if (targetSocket) allSockets.delete(targetSocket);
          });

          targetSocket.on('error', () => {
            clientSocket.write(
              Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            );
            clientSocket.destroy();
          });
          targetSocket.on('close', () => {
            clientSocket.destroy();
          });
        }
      };

      clientSocket.on('data', onData);
      clientSocket.on('close', () => {
        targetSocket?.destroy();
      });
      clientSocket.on('error', () => {
        targetSocket?.destroy();
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      resolve({
        server,
        port: addr.port,
        get connectionsCount() {
          return connectionsCount;
        },
        get lastRequestedHost() {
          return lastRequestedHost;
        },
        get lastRequestedPort() {
          return lastRequestedPort;
        },
        close: () => {
          for (const s of allSockets) s.destroy();
          return new Promise<void>((res) => server.close(() => res()));
        },
      });
    });
    server.on('error', reject);
  });
}

const cleanupTasks: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const task of cleanupTasks.splice(0).reverse()) {
    try {
      await task();
    } catch {
      // ignore teardown errors
    }
  }
});

describe('Tor / SOCKS5 Proxy Integration', () => {
  it('connects a raw TcpSocket through a SOCKS5 proxy to an IPv4 destination', async () => {
    let receivedData = '';
    const destination = createTrackedServer((sock) => {
      sock.on('data', (d) => {
        receivedData += d.toString('utf8');
        sock.write('PONG\n');
      });
    });
    const destPort = await destination.listen();
    cleanupTasks.push(destination.close);

    const proxy = await createMockSocks5Proxy();
    cleanupTasks.push(proxy.close);

    const client = TcpSocket.createConnection({
      host: '127.0.0.1',
      port: destPort,
      proxy: {
        host: '127.0.0.1',
        port: proxy.port,
      },
    });
    cleanupTasks.push(() => client.destroy());

    const responsePromise = new Promise<string>((resolve) => {
      client.on('data', (chunk) => resolve(String(chunk)));
    });

    client.write('PING\n', 'utf8');

    expect(await responsePromise).toBe('PONG\n');
    expect(receivedData).toBe('PING\n');
    expect(proxy.connectionsCount).toBe(1);
    expect(proxy.lastRequestedHost).toBe('127.0.0.1');
    expect(proxy.lastRequestedPort).toBe(destPort);
  });

  it('connects to a simulated .onion hidden service via SOCKS5 domain name resolution', async () => {
    let receivedOnionData = '';
    const onionService = createTrackedServer((sock) => {
      sock.on('data', (d) => {
        receivedOnionData += d.toString('utf8');
        sock.write('ONION_PONG\n');
      });
    });
    const localPort = await onionService.listen();
    cleanupTasks.push(onionService.close);

    const onionAddress = 'vww6ym3v6example7qd.onion';
    const proxy = await createMockSocks5Proxy({
      [onionAddress]: { host: '127.0.0.1', port: localPort },
    });
    cleanupTasks.push(proxy.close);

    const client = TcpSocket.createConnection({
      host: onionAddress,
      port: 8080,
      proxy: {
        host: '127.0.0.1',
        port: proxy.port,
      },
    });
    cleanupTasks.push(() => client.destroy());

    const responsePromise = new Promise<string>((resolve) => {
      client.on('data', (chunk) => resolve(String(chunk)));
    });

    client.write('SECRET_ONION_MSG\n', 'utf8');

    expect(await responsePromise).toBe('ONION_PONG\n');
    expect(receivedOnionData).toBe('SECRET_ONION_MSG\n');
    expect(proxy.connectionsCount).toBe(1);
    expect(proxy.lastRequestedHost).toBe(onionAddress);
    expect(proxy.lastRequestedPort).toBe(8080);
  });

  it('runs an authenticated, encrypted P2PTcpPeer session through a Tor SOCKS5 proxy with torMode', async () => {
    const proxy = await createMockSocks5Proxy();
    cleanupTasks.push(proxy.close);

    const host = new P2PTcpPeer();
    const guest = new P2PTcpPeer({
      proxy: { host: '127.0.0.1', port: proxy.port },
      torMode: true,
    });
    cleanupTasks.push(() => {
      host.close();
      guest.close();
    });

    function connected(peer: P2PTcpPeer) {
      return new Promise<void>((resolve, reject) => {
        peer.on('state', (state) => {
          if (state === 'connected') resolve();
        });
        peer.on('error', reject);
      });
    }

    const connections = Promise.all([connected(host), connected(guest)]);
    const offer = await host.createOffer({
      advertiseHost: '127.0.0.1',
      listenHost: '127.0.0.1',
    });
    await host.acceptAnswer(await guest.acceptOffer(offer));
    await connections;

    // Verify proxy routed guest's TCP connection
    expect(proxy.connectionsCount).toBe(1);
    expect(proxy.lastRequestedHost).toBe('127.0.0.1');

    // Exchange encrypted messages
    const guestReceived = new Promise((resolve) =>
      guest.on('message', resolve)
    );
    host.sendMessage({ text: 'Hello Tor peer!' });
    expect(await guestReceived).toMatchObject({
      payload: { text: 'Hello Tor peer!' },
    });

    const hostReceived = new Promise((resolve) => host.on('message', resolve));
    guest.sendMessage({ text: 'Tor reply from anonymous guest' });
    expect(await hostReceived).toMatchObject({
      payload: { text: 'Tor reply from anonymous guest' },
    });
  });

  it('manages a ReliableConversation with torProxy and torOnly', async () => {
    const proxy = await createMockSocks5Proxy();
    cleanupTasks.push(proxy.close);

    const memStorage = (): KeyValueStorage => {
      const map = new Map<string, string>();
      return {
        async getItem(k: string) {
          return map.get(k) ?? null;
        },
        async setItem(k: string, v: string) {
          map.set(k, v);
        },
      };
    };

    const hostIdentity = await loadOrCreateIdentity(memStorage());
    const guestIdentity = await loadOrCreateIdentity(memStorage());
    const hostStorage = await createEncryptedStorage(
      memStorage(),
      memStorage()
    );
    const guestStorage = await createEncryptedStorage(
      memStorage(),
      memStorage()
    );

    let hostSignalingHandler: ((m: string) => void) | null = null;
    let guestSignalingHandler: ((m: string) => void) | null = null;

    const hostSignaling: SignalTransport = {
      start(handlers) {
        hostSignalingHandler = handlers.onMessage;
        handlers.onOnline(true);
      },
      send(msg) {
        setImmediate(() => guestSignalingHandler?.(msg));
        return true;
      },
      stop() {},
    };

    const guestSignaling: SignalTransport = {
      start(handlers) {
        guestSignalingHandler = handlers.onMessage;
        handlers.onOnline(true);
      },
      send(msg) {
        setImmediate(() => hostSignalingHandler?.(msg));
        return true;
      },
      stop() {},
    };

    const hostConv = new ReliableConversation({
      identity: hostIdentity,
      remotePublicKey: guestIdentity.publicKey,
      conversationId: 'tor-test-conv',
      role: 'host',
      storage: hostStorage,
      signaling: hostSignaling,
      getHostOptions: () => ({
        advertiseHost: '127.0.0.1',
        listenHost: '127.0.0.1',
      }),
    });

    const guestConv = new ReliableConversation({
      identity: guestIdentity,
      remotePublicKey: hostIdentity.publicKey,
      conversationId: 'tor-test-conv',
      role: 'guest',
      storage: guestStorage,
      signaling: guestSignaling,
      torProxy: {
        host: '127.0.0.1',
        port: proxy.port,
      },
      torOnly: true,
    });

    cleanupTasks.push(() => {
      hostConv.stop();
      guestConv.stop();
    });

    await hostConv.start();
    await guestConv.start();

    await new Promise<void>((resolve) => {
      guestConv.on('state', (state) => {
        if (state === 'connected') resolve();
      });
    });

    expect(proxy.connectionsCount).toBeGreaterThanOrEqual(1);

    const receivedOnGuest = new Promise<void>((resolve) => {
      guestConv.on('messages', (msgs) => {
        if (msgs.some((m) => m.payload === 'Reliable Tor message')) {
          resolve();
        }
      });
    });

    await hostConv.sendMessage('Reliable Tor message');
    await receivedOnGuest;
  });

  it('enforces empty iceServers when torMode is enabled', () => {
    const peerWithStun = new P2PTcpPeer({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
      torMode: true,
    });
    // Access internal options to verify iceServers was suppressed
    const internal = peerWithStun as unknown as {
      options: { iceServers: unknown[] };
    };
    expect(internal.options.iceServers).toEqual([]);
    peerWithStun.close();
  });

  it('emits an error when SOCKS5 proxy rejects connection', async () => {
    // Start a server that rejects SOCKS5 handshake (e.g. returns 0x05, 0xFF - No acceptable auth)
    const badProxy = createTrackedServer((sock) => {
      sock.on('data', () => {
        sock.write(Buffer.from([0x05, 0xff]));
      });
    });
    const proxyPort = await badProxy.listen();
    cleanupTasks.push(badProxy.close);

    const client = TcpSocket.createConnection({
      host: '127.0.0.1',
      port: 9999,
      proxy: {
        host: '127.0.0.1',
        port: proxyPort,
      },
    });
    cleanupTasks.push(() => client.destroy());

    const errorPromise = new Promise<Error>((resolve) => {
      client.on('error', resolve);
    });

    const error = await errorPromise;
    expect(error.message).toContain('SOCKS5 proxy rejected handshake');
  });

  it('rejects hostnames exceeding SOCKS5 255-byte limit', async () => {
    const proxy = await createMockSocks5Proxy();
    cleanupTasks.push(proxy.close);

    const longHostname = `${'a'.repeat(256)}.onion`;
    const client = TcpSocket.createConnection({
      host: longHostname,
      port: 80,
      proxy: {
        host: '127.0.0.1',
        port: proxy.port,
      },
    });
    cleanupTasks.push(() => client.destroy());

    const errorPromise = new Promise<Error>((resolve) => {
      client.on('error', resolve);
    });

    const error = await errorPromise;
    expect(error.message).toContain('limit of 255 bytes');
  });
});
