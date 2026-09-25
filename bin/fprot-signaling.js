#!/usr/bin/env node
import { createSignalingServer } from '../server/signaling.mjs';

const token = process.env.FPROT_SIGNAL_TOKEN || process.argv[2];
if (!token || token.length < 32) {
  process.stderr.write(
    'Error: FPROT_SIGNAL_TOKEN environment variable (or argument, min 32 chars) is required.\n' +
      'Example: FPROT_SIGNAL_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 fprot-signaling\n'
  );
  process.exit(1);
}

const server = createSignalingServer({
  token,
  host: process.env.FPROT_SIGNAL_HOST ?? '127.0.0.1',
  port: Number(process.env.FPROT_SIGNAL_PORT ?? 8787),
});

server.on('listening', () => {
  const addr = server.address();
  process.stdout.write(
    `[fprot] Signaling server running at ws://${addr.address}:${addr.port}\n`
  );
});

server.on('error', (error) => {
  process.stderr.write(`[fprot] Server error: ${error.message}\n`);
  process.exit(1);
});

const shutdown = () => {
  for (const socket of server.clients) socket.terminate();
  server.close();
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
