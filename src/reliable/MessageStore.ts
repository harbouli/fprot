import type { JsonValue } from '../types';
import type { ChatMessage, KeyValueStorage } from './types';

export const MAX_MESSAGE_BYTES = 16 * 1024;
export const MAX_MESSAGES = 2000;

export function validatePayload(
  payload: unknown
): asserts payload is JsonValue {
  const json = JSON.stringify(payload);
  if (typeof json !== 'string' || json.length > MAX_MESSAGE_BYTES / 6) {
    throw new Error(
      'Message must be JSON and at most 2730 characters when serialized'
    );
  }
  // JSON.stringify silently drops undefined/functions and converts NaN. Reject those.
  JSON.stringify(payload, (_key, value: unknown) => {
    if (
      value === undefined ||
      typeof value === 'function' ||
      typeof value === 'symbol' ||
      (typeof value === 'number' && !Number.isFinite(value))
    ) {
      throw new Error('Message contains a non-JSON value');
    }
    return value;
  });
}

/** Single-writer journal. Snapshot replacement commits before memory or UI changes. */
export class MessageStore {
  private rows: ChatMessage[] = [];
  private queue: Promise<unknown> = Promise.resolve();
  constructor(
    private storage: KeyValueStorage,
    private key: string
  ) {}

  async load(): Promise<void> {
    const saved = await this.storage.getItem(this.key);
    if (saved === null) return;
    const data = JSON.parse(saved);
    if (
      data.v !== 1 ||
      !Array.isArray(data.messages) ||
      data.messages.length > MAX_MESSAGES
    )
      throw new Error('Invalid conversation storage');
    const seen = new Set<string>();
    for (const row of data.messages) {
      if (
        !row ||
        typeof row.id !== 'string' ||
        !/^[A-Za-z0-9_-]{16}$/.test(row.id) ||
        !Number.isFinite(row.sentAt) ||
        !['incoming', 'outgoing'].includes(row.direction) ||
        !['pending', 'delivered'].includes(row.status)
      )
        throw new Error('Invalid stored message');
      validatePayload(row.payload);
      const id = `${row.direction}:${row.id}`;
      if (seen.has(id)) throw new Error('Duplicate stored message');
      seen.add(id);
    }
    this.rows = data.messages;
  }

  snapshot(): ChatMessage[] {
    return JSON.parse(JSON.stringify(this.rows));
  }
  pending(): ChatMessage | undefined {
    return this.snapshot().find(
      (row) => row.direction === 'outgoing' && row.status === 'pending'
    );
  }

  private transaction<T>(change: (rows: ChatMessage[]) => T): Promise<T> {
    const operation = this.queue.then(async () => {
      const rows = this.snapshot();
      const result = change(rows);
      await this.storage.setItem(
        this.key,
        JSON.stringify({ v: 1, messages: rows })
      );
      this.rows = rows;
      return result;
    });
    this.queue = operation.catch(() => {});
    return operation;
  }

  add(message: ChatMessage): Promise<boolean> {
    validatePayload(message.payload);
    const safe = JSON.parse(JSON.stringify(message)) as ChatMessage;
    return this.transaction((rows) => {
      const previous = rows.find(
        (row) => row.id === safe.id && row.direction === safe.direction
      );
      if (previous) {
        if (
          previous.sentAt !== safe.sentAt ||
          JSON.stringify(previous.payload) !== JSON.stringify(safe.payload)
        )
          throw new Error('Message ID reused with different contents');
        return false;
      }
      if (rows.length >= MAX_MESSAGES)
        throw new Error(
          'Conversation storage full (2000 messages). Export/archive before continuing.'
        );
      rows.push(safe);
      return true;
    });
  }

  acknowledge(id: string): Promise<void> {
    return this.transaction((rows) => {
      const row = rows.find(
        (message) => message.id === id && message.direction === 'outgoing'
      );
      if (row) row.status = 'delivered';
    });
  }
}
