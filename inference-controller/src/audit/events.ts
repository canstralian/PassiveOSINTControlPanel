/**
 * Domain event logger.
 *
 * Lower-cost than audit; records graph deltas, mode changes, etc. Domain
 * events are NOT a substitute for audit — both are required at the
 * appropriate stages of the control chain.
 */
import type { DomainEvent } from "../domain/types.js";

export class EventLogger {
  private readonly events: DomainEvent[] = [];

  emit(event: DomainEvent): void {
    // Defensive copy: callers must not be able to mutate stored events.
    this.events.push(structuredClone(event));
  }

  all(): readonly DomainEvent[] {
    return this.events.slice();
  }

  byInvestigation(investigationId: string): readonly DomainEvent[] {
    return this.events.filter((e) => e.investigationId === investigationId);
  }
}
