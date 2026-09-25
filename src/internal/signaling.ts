export const SIGNAL_VERSION = 1;

export interface SignalEnvelope {
  v: number;
  type: 'offer' | 'answer';
  sdp: string;
}

export function encodeSignal(type: 'offer' | 'answer', sdp: string): string {
  return JSON.stringify({ v: SIGNAL_VERSION, type, sdp });
}

export function decodeSignal(
  input: string,
  expectedType: 'offer' | 'answer'
): SignalEnvelope {
  let value: unknown;
  try {
    value = JSON.parse(input);
  } catch {
    throw new Error('The signaling string is not valid JSON');
  }

  if (
    typeof value !== 'object' ||
    value === null ||
    (value as Partial<SignalEnvelope>).v !== SIGNAL_VERSION ||
    (value as Partial<SignalEnvelope>).type !== expectedType ||
    typeof (value as Partial<SignalEnvelope>).sdp !== 'string'
  ) {
    throw new Error(`Expected a version 1 WebRTC ${expectedType}`);
  }
  return value as SignalEnvelope;
}
