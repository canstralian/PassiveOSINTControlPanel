/**
 * Append-only audit logger with hash-chain integrity and fail-closed mode.
 *
 * Failure to write an audit event must cause the calling operation to fail
 * closed. The logger exposes `failClosed` so callers (and tests) can verify
 * the system has entered fail-closed mode.
 */
import { createHash } from "node:crypto";
import { mkdir, appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEvent } from "../domain/types.js";
import { AuditEvent as AuditEventSchema } from "../domain/types.js";
import { newAuditEventId } from "../domain/ids.js";

export type AuditSink = {
  /** Write a fully-formed audit event. Throws on failure. */
  write(event: AuditEvent): Promise<void>;
  /** Return all events written so far (for tests / replay). */
  read(): Promise<AuditEvent[]>;
};

export class InMemoryAuditSink implements AuditSink {
  private readonly events: AuditEvent[] = [];
  private readonly _injectFailure: boolean;

  constructor(opts: { failOnWrite?: boolean } = {}) {
    this._injectFailure = opts.failOnWrite ?? false;
  }

  async write(event: AuditEvent): Promise<void> {
    if (this._injectFailure) {
      throw new Error("InMemoryAuditSink injected failure");
    }
    this.events.push(event);
  }

  async read(): Promise<AuditEvent[]> {
    return [...this.events];
  }
}

export class JsonlFileAuditSink implements AuditSink {
  constructor(private readonly path: string) {}

  async write(event: AuditEvent): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    await appendFile(this.path, JSON.stringify(event) + "\n", "utf8");
  }

  async read(): Promise<AuditEvent[]> {
    const { readFile } = await import("node:fs/promises");
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    return text
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => AuditEventSchema.parse(JSON.parse(line)));
  }
}

export type AuditPayload = Omit<AuditEvent, "id" | "timestamp" | "integrityMarker">;

export class AuditLogger {
  private _failClosed = false;
  private _lastIntegrityMarker = "GENESIS";

  constructor(private readonly sink: AuditSink) {}

  get failClosed(): boolean {
    return this._failClosed;
  }

  /**
   * Write an audit event. Returns the persisted event. Throws and enters
   * fail-closed mode if the sink rejects the write.
   */
  async record(payload: AuditPayload, now: Date = new Date()): Promise<AuditEvent> {
    if (this._failClosed) {
      throw new Error("AuditLogger is in fail-closed mode");
    }
    const id = newAuditEventId();
    const timestamp = now.toISOString();
    const integrityMarker = this.computeIntegrityMarker(
      this._lastIntegrityMarker,
      id,
      timestamp,
      payload
    );
    const event: AuditEvent = {
      ...payload,
      id,
      timestamp,
      integrityMarker,
    };
    const parsed = AuditEventSchema.parse(event);
    try {
      await this.sink.write(parsed);
    } catch (err) {
      // Per spec point 3: audit failure -> fail closed.
      this._failClosed = true;
      throw err;
    }
    this._lastIntegrityMarker = integrityMarker;
    return parsed;
  }

  async readAll(): Promise<AuditEvent[]> {
    return this.sink.read();
  }

  private computeIntegrityMarker(
    previous: string,
    id: string,
    timestamp: string,
    payload: AuditPayload
  ): string {
    const canonical = JSON.stringify({ previous, id, timestamp, payload });
    return createHash("sha256").update(canonical).digest("hex");
  }
}

/**
 * Verify the chain of integrity markers across an ordered list of events.
 * The first event's integrity marker is computed from "GENESIS".
 */
export function verifyAuditChain(events: AuditEvent[]): { ok: boolean; brokenAt?: number } {
  let previous = "GENESIS";
  for (let i = 0; i < events.length; i++) {
    const ev = events[i]!;
    const { id, timestamp, integrityMarker, ...rest } = ev;
    const expected = createHash("sha256")
      .update(JSON.stringify({ previous, id, timestamp, payload: rest }))
      .digest("hex");
    if (expected !== integrityMarker) {
      return { ok: false, brokenAt: i };
    }
    previous = integrityMarker;
  }
  return { ok: true };
}
