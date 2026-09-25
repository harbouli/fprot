import { sign, verify } from './identity';
import type { PeerIdentity } from './types';

export interface Signal {
  v: 1;
  conversationId: string;
  from: string;
  to: string;
  type: 'wake' | 'request' | 'offer' | 'answer';
  challenge: string;
  attempt: string;
  sdp: string;
}

export function encodeSignal(signal: Signal, identity: PeerIdentity): string {
  const body = JSON.stringify(signal);
  return JSON.stringify({
    body,
    signature: sign(`fprot.signaling.v1:${body}`, identity),
  });
}

export function decodeSignal(
  raw: string,
  localKey: string,
  remoteKey: string,
  conversationId: string
): Signal {
  if (raw.length > 128 * 1024) throw new Error('Signal too large');
  const envelope = JSON.parse(raw);
  if (
    typeof envelope.body !== 'string' ||
    typeof envelope.signature !== 'string' ||
    !verify(
      `fprot.signaling.v1:${envelope.body}`,
      envelope.signature,
      remoteKey
    )
  )
    throw new Error('Peer signaling signature is invalid');
  const signal = JSON.parse(envelope.body);
  if (
    signal.v !== 1 ||
    signal.from !== remoteKey ||
    signal.to !== localKey ||
    signal.conversationId !== conversationId ||
    !['wake', 'request', 'offer', 'answer'].includes(signal.type) ||
    typeof signal.challenge !== 'string' ||
    typeof signal.attempt !== 'string' ||
    typeof signal.sdp !== 'string'
  )
    throw new Error('Invalid signaling scope');
  if (signal.type !== 'wake' && !/^[A-Za-z0-9_-]{16}$/.test(signal.challenge))
    throw new Error('Invalid signaling challenge');
  if (
    ['offer', 'answer'].includes(signal.type) &&
    !/^[A-Za-z0-9_-]{16}$/.test(signal.attempt)
  )
    throw new Error('Invalid signaling attempt');
  return signal;
}
