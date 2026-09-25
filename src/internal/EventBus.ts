import type { PeerEventMap, Unsubscribe } from '../types';

export class EventBus<Events = PeerEventMap> {
  private readonly listeners = new Map<
    keyof Events,
    Set<(value: any) => void>
  >();

  on<K extends keyof Events>(
    event: K,
    listener: (value: Events[K]) => void
  ): Unsubscribe {
    const bucket = this.listeners.get(event) ?? new Set();
    bucket.add(listener);
    this.listeners.set(event, bucket);
    return () => bucket.delete(listener);
  }

  emit<K extends keyof Events>(event: K, value: Events[K]): void {
    this.listeners.get(event)?.forEach((listener) => listener(value));
  }

  clear(): void {
    this.listeners.clear();
  }
}
