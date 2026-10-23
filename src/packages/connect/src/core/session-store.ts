/**
 * ADOPT-1.1 pluggable session storage — first implementation:
 * InMemoryAskMIConnectSessionStore. Concurrent-session safe for ordinary
 * single-process use (single-threaded Map operations are atomic); no global
 * singleton state. The interface is designed so a Redis/DB store is not
 * awkward.
 */

import type { AskMIConnectSession, AskMIConnectSessionStore } from './types';

export class InMemoryAskMIConnectSessionStore implements AskMIConnectSessionStore {
  private readonly sessions = new Map<string, AskMIConnectSession>();
  private readonly consumed = new Set<string>();

  async create(session: AskMIConnectSession): Promise<void> {
    if (this.sessions.has(session.sessionId)) {
      throw new Error(`session id collision: ${session.sessionId}`);
    }
    this.sessions.set(session.sessionId, session);
  }

  async get(sessionId: string): Promise<AskMIConnectSession | null> {
    return this.sessions.get(sessionId) ?? null;
  }

  async update(session: AskMIConnectSession): Promise<void> {
    if (!this.sessions.has(session.sessionId)) {
      throw new Error(`cannot update unknown session: ${session.sessionId}`);
    }
    this.sessions.set(session.sessionId, session);
  }

  /**
   * One-shot consume: atomically claims the session for a completion
   * attempt. A second consume for the same session returns null (replay).
   * The session record itself stays readable via get() so status remains
   * observable after the attempt.
   */
  async consume(sessionId: string): Promise<AskMIConnectSession | null> {
    if (this.consumed.has(sessionId)) return null;
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    this.consumed.add(sessionId);
    return session;
  }

  /** Remove sessions whose expiry elapsed (or already expired). Returns the count. */
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
