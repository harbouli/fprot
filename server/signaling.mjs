#!/usr/bin/env node
import {
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify,
} from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';

// Coordination only: no TCP chat relay, message mailbox, or disk persistence.
export function createSignalingServer({
  token,
  host = '127.0.0.1',
  port = 8787,
}) {
  if (typeof token !== 'string' || token.length < 32)
    throw new Error('Set FPROT_SIGNAL_TOKEN to at least 32 random characters');
  const server = new WebSocketServer({
    host,
    port,
    maxPayload: 132 * 1024,
    perMessageDeflate: false,
  });
  const peers = new Map();
  server.on('connection', (socket) => {
    if (server.clients.size > 100) {
      socket.close(1013, 'Server full');
      return;
    }
    const nonce = randomBytes(32).toString('hex');
    let publicKey;
    let alive = true;
    let count = 0;
    let windowStart = Date.now();
    const authTimeout = setTimeout(
      () => socket.close(1008, 'Authentication timeout'),
      10_000
    );
    const pulse = setInterval(() => {
      if (!alive) {
        socket.terminate();
        return;
      }
      alive = false;
      socket.ping();
    }, 30_000);
    socket.on('pong', () => {
      alive = true;
    });
    socket.on('error', () => socket.terminate());
    socket.send(JSON.stringify({ type: 'challenge', nonce }));
    socket.on('message', (bytes, binary) => {
      try {
        if (binary) throw new Error('Text only');
        if (Date.now() - windowStart > 60_000) {
          count = 0;
          windowStart = Date.now();
        }
        if (++count > 120) throw new Error('Rate limit');
        const message = JSON.parse(bytes.toString());
        if (!publicKey) {
          if (
            message.type !== 'auth' ||
            typeof message.token !== 'string' ||
            typeof message.publicKey !== 'string' ||
            typeof message.signature !== 'string'
          )
            throw new Error('Authentication required');
          const supplied = Buffer.from(message.token);
          const expected = Buffer.from(token);
          if (
            supplied.length !== expected.length ||
            !timingSafeEqual(supplied, expected)
          )
            throw new Error('Authentication failed');
          const rawKey = Buffer.from(message.publicKey, 'base64url');
          if (
            rawKey.length !== 32 ||
            rawKey.toString('base64url') !== message.publicKey
          )
            throw new Error('Invalid identity');
          const key = createPublicKey({
            key: Buffer.concat([
              Buffer.from('302a300506032b6570032100', 'hex'),
              rawKey,
            ]),
            format: 'der',
            type: 'spki',
          });
          if (
            !verify(
              null,
              Buffer.from(`fprot.broker.v1:${nonce}`),
              key,
              Buffer.from(message.signature, 'base64url')
            )
          )
            throw new Error('Invalid proof');
          publicKey = message.publicKey;
          peers.get(publicKey)?.close(1000, 'Identity reconnected');
          peers.set(publicKey, socket);
          clearTimeout(authTimeout);
          socket.send(JSON.stringify({ type: 'ready' }));
          return;
        }
        if (
          message.type !== 'signal' ||
          typeof message.data !== 'string' ||
          message.data.length > 128 * 1024
        )
          throw new Error('Invalid signal');
        const envelope = JSON.parse(message.data);
        const body = JSON.parse(envelope.body);
        if (body.from !== publicKey || typeof body.to !== 'string')
          throw new Error('Invalid sender');
        const destination = peers.get(body.to);
        if (destination?.readyState === WebSocket.OPEN)
          destination.send(
            JSON.stringify({ type: 'signal', data: message.data })
          );
      } catch {
        socket.close(1008, 'Invalid or unauthorized request');
      }
    });
    socket.on('close', () => {
      clearTimeout(authTimeout);
      clearInterval(pulse);
      if (publicKey && peers.get(publicKey) === socket) peers.delete(publicKey);
    });
  });
  return server;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const server = createSignalingServer({
    token: process.env.FPROT_SIGNAL_TOKEN,
    host: process.env.FPROT_SIGNAL_HOST ?? '127.0.0.1',
    port: Number(process.env.FPROT_SIGNAL_PORT ?? 8787),
  });
  server.on('listening', () =>
    process.stdout.write(
      `fprot signaling listening on ${JSON.stringify(server.address())}\n`
    )
  );
  server.on('error', (error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
  const shutdown = () => {
    for (const socket of server.clients) socket.terminate();
    server.close();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
