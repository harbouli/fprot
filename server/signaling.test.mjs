import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { generateKeyPairSync, sign } from 'node:crypto';
import { WebSocket } from 'ws';
import { createSignalingServer } from './signaling.mjs';

function identity() {
  const pair = generateKeyPairSync('ed25519');
  return {
    ...pair,
    id: pair.publicKey
      .export({ type: 'spki', format: 'der' })
      .subarray(-32)
      .toString('base64url'),
  };
}

async function fixture(t) {
  const token = 'test-only-capability-01234567890123456789';
  const server = createSignalingServer({ token, port: 0 });
  await once(server, 'listening');
  t.after(async () => {
    for (const socket of server.clients) socket.terminate();
    await new Promise((resolve) => server.close(resolve));
  });
  return { token, url: `ws://127.0.0.1:${server.address().port}` };
}

async function authenticate(url, token, keys, claimed = keys.id) {
  const socket = new WebSocket(url);
  const [raw] = await once(socket, 'message');
  const { nonce } = JSON.parse(raw);
  const result = Promise.race([
    once(socket, 'message').then(([message]) => JSON.parse(message)),
    once(socket, 'close').then(() => ({ type: 'rejected' })),
  ]);
  socket.send(
    JSON.stringify({
      type: 'auth',
      token,
      publicKey: claimed,
      signature: sign(
        null,
        Buffer.from(`fprot.broker.v1:${nonce}`),
        keys.privateKey
      ).toString('base64url'),
    })
  );
  return { socket, response: await result };
}

test(
  'routes authenticated signaling, reconnects identity, and rejects spoofed senders',
  { timeout: 5000 },
  async (t) => {
    const { token, url } = await fixture(t);
    const a = identity();
    const b = identity();
    const alice = await authenticate(url, token, a);
    const bob = await authenticate(url, token, b);
    assert.equal(alice.response.type, 'ready');
    assert.equal(bob.response.type, 'ready');
    const data = JSON.stringify({
      body: JSON.stringify({ from: a.id, to: b.id }),
      signature: 'verified-by-recipient',
    });
    const received = once(bob.socket, 'message');
    alice.socket.send(JSON.stringify({ type: 'signal', data }));
    assert.equal(JSON.parse((await received)[0]).data, data);
    const previousClosed = once(bob.socket, 'close');
    const newBob = await authenticate(url, token, b);
    assert.equal(newBob.response.type, 'ready');
    await previousClosed;
    const rejected = once(alice.socket, 'close');
    alice.socket.send(
      JSON.stringify({
        type: 'signal',
        data: JSON.stringify({
          body: JSON.stringify({ from: b.id, to: a.id }),
        }),
      })
    );
    assert.equal((await rejected)[0], 1008);
  }
);

test(
  'rejects wrong tokens and public keys without proof of possession',
  { timeout: 5000 },
  async (t) => {
    const { token, url } = await fixture(t);
    const a = identity();
    const b = identity();
    assert.equal(
      (await authenticate(url, 'wrong', a)).response.type,
      'rejected'
    );
    assert.equal(
      (await authenticate(url, token, a, b.id)).response.type,
      'rejected'
    );
  }
);
