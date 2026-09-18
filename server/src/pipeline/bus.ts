/**
 * Progress bus (CONTRACTS §9.5 / DESIGN §7): one EventEmitter per run, with a ring buffer so a browser tab that
 * reconnects to `GET /api/runs/:id/events` after a network blip does not miss anything that happened while it was
 * away. A heartbeat keeps the SSE connection alive through proxies/timeouts that close idle sockets.
 */
import { EventEmitter } from 'node:events';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import type { ProgressEvent, StageId, StageStatus } from '@shared/pipeline.js';

const RING_BUFFER_SIZE = 500;
const HEARTBEAT_MS = 15_000;

export interface BufferedEvent {
  seq: number;
  event: ProgressEvent;
}

/** One run's event stream: recent events kept in memory, new ones both emitted live and appended to the buffer. */
export type BusSink = (buffered: BufferedEvent) => void;

export class RunBus {
  private readonly emitter = new EventEmitter();
  private readonly buffer: BufferedEvent[] = [];
  private nextSeq = 1;

  constructor(
    readonly runId: string,
    private readonly sink?: BusSink,
  ) {
    this.emitter.setMaxListeners(50);
  }

  publish(event: ProgressEvent): void {
    const buffered: BufferedEvent = { seq: this.nextSeq++, event };
    this.buffer.push(buffered);
    if (this.buffer.length > RING_BUFFER_SIZE) this.buffer.shift();
    this.emitter.emit('event', buffered);
    try {
      this.sink?.(buffered);
    } catch {
      // A full disk must not stop the build; the live stream still has the event.
    }
  }

  stage(stage: StageId, status: StageStatus, message: string, data?: unknown): void {
    this.publish({ runId: this.runId, type: 'stage', stage, status, message, at: new Date().toISOString(), ...(data !== undefined ? { data } : {}) });
  }

  log(message: string, stage?: StageId): void {
    this.publish({ runId: this.runId, type: 'log', message, at: new Date().toISOString(), ...(stage ? { stage } : {}) });
  }

  llm(message: string, data?: unknown): void {
    this.publish({ runId: this.runId, type: 'llm', message, at: new Date().toISOString(), ...(data !== undefined ? { data } : {}) });
  }

  done(message: string, data?: unknown): void {
    this.publish({ runId: this.runId, type: 'done', message, at: new Date().toISOString(), ...(data !== undefined ? { data } : {}) });
  }

  error(message: string, data?: unknown): void {
    this.publish({ runId: this.runId, type: 'error', message, at: new Date().toISOString(), ...(data !== undefined ? { data } : {}) });
  }

  /** Events strictly after `sinceSeq` (or everything when omitted), for the initial SSE flush / reconnect. */
  since(sinceSeq?: number): BufferedEvent[] {
    if (sinceSeq === undefined) return [...this.buffer];
    return this.buffer.filter((b) => b.seq > sinceSeq);
  }

  get lastSeq(): number {
    return this.buffer.length > 0 ? this.buffer[this.buffer.length - 1]!.seq : 0;
  }

  /** Subscribes to live events; returns an unsubscribe function. */
  subscribe(listener: (b: BufferedEvent) => void): () => void {
    this.emitter.on('event', listener);
    return () => this.emitter.off('event', listener);
  }
}

/** All runs' buses for this server process (runs do not survive a restart; `persist.ts` marks them interrupted). */
export class RunBusRegistry {
  private readonly buses = new Map<string, RunBus>();

  /** `sinkFor` gives a bus somewhere to write each event as well (the worker appends to the run's events file). */
  constructor(private readonly sinkFor?: (runId: string) => BusSink | undefined) {}

  get(runId: string): RunBus {
    let bus = this.buses.get(runId);
    if (!bus) {
      bus = new RunBus(runId, this.sinkFor?.(runId));
      this.buses.set(runId, bus);
    }
    return bus;
  }

  has(runId: string): boolean {
    return this.buses.has(runId);
  }

  delete(runId: string): void {
    this.buses.delete(runId);
  }
}

/** Writes an SSE `progress` event for one buffered item. */
export function formatSseEvent(buffered: BufferedEvent): string {
  return `id: ${buffered.seq}\nevent: progress\ndata: ${JSON.stringify(buffered.event)}\n\n`;
}

/** A sink that appends each event as one JSON line, the format `tailEventsFile` reads. */
export function fileSink(file: string): BusSink {
  return (buffered) => appendFileSync(file, `${JSON.stringify(buffered)}\n`);
}

/** Events with seq > since from an events file written by `fileSink`; a damaged line is skipped. */
export function readEventsFile(file: string, since?: number): BufferedEvent[] {
  if (!existsSync(file)) return [];
  const out: BufferedEvent[] = [];
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line) continue;
    try {
      const parsed = JSON.parse(line) as BufferedEvent;
      if (typeof parsed.seq === 'number' && (since === undefined || parsed.seq > since)) out.push(parsed);
    } catch {
      // skip
    }
  }
  return out;
}

export function formatSseHeartbeat(): string {
  return `: heartbeat ${new Date().toISOString()}\n\n`;
}

export const SSE_HEARTBEAT_MS = HEARTBEAT_MS;
