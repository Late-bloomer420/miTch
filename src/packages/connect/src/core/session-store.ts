/**
 * Single-process store. Each read/consume/update performs its state/TTL check
 * and Map mutation without awaiting: the operation is atomic in this topology.
 * This is not evidence for a multi-process or durable store.
 */
import type {
  AskMIConnectSession,
  AskMIConnectSessionStore,
  AskMIConnectSessionUpdate,
  AskMIConnectSessionUpdateResult,
} from './types';

export class InMemoryAskMIConnectSessionStore implements AskMIConnectSessionStore {
  private readonly sessions = new Map<string, AskMIConnectSession>();
  private readonly consumed = new Set<string>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  /** Called only inside synchronous store operations, including the final write. */
  private current(sessionId: string): AskMIConnectSession | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    if (
      (session.status === 'pending' || session.status === 'wallet_opened') &&
      Date.parse(session.expiresAt) <= this.now()
    ) {
      const expired: AskMIConnectSession = { ...session, status: 'expired' };
      this.sessions.set(sessionId, expired);
      return expired;
    }
    return session;
  }

  async create(session: AskMIConnectSession): Promise<void> {
    if (this.sessions.has(session.sessionId)) {
      throw new Error(`session id collision: ${session.sessionId}`);
    }
    // Own the stored record; callers must not mutate the lifecycle by reference.
    this.sessions.set(session.sessionId, structuredClone(session));
  }

  async get(sessionId: string): Promise<AskMIConnectSession | null> {
    return structuredClone(this.current(sessionId));
  }

  async update(
    sessionId: string,
    update: AskMIConnectSessionUpdate
  ): Promise<AskMIConnectSessionUpdateResult> {
    const current = this.current(sessionId);
    if (!current || (current.status !== 'pending' && current.status !== 'wallet_opened')) {
      return { applied: false, session: structuredClone(current) };
    }
    const session: AskMIConnectSession = { ...current, ...structuredClone(update) };
    this.sessions.set(sessionId, session);
    return { applied: true, session: structuredClone(session) };
  }

  /** One consumed attempt, including resolver failure. Never release for retry. */
  async consume(sessionId: string): Promise<AskMIConnectSession | null> {
    const session = this.current(sessionId);
    if (!session || this.consumed.has(sessionId)) return null;
    this.consumed.add(sessionId);
    return structuredClone(session);
  }

  /** Remove elapsed records; an in-flight update cannot recreate one. */
  async deleteExpired(now: Date): Promise<number> {
    const t = now.getTime();
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (session.status === 'expired' || Date.parse(session.expiresAt) <= t) {
        this.sessions.delete(id);
        this.consumed.delete(id);
        removed++;
      }
    }
    return removed;
  }
}
