/**
 * KPI + Observability Module (Specs 38-40, 65-66, 72-75, 81, 86-89, 92, 98-99)
 *
 * Security Profile Score, deny visibility, alert thresholds, soft-fail mode,
 * cost estimation, WebAuthn drift, resolver metrics.
 */

// ─── Types ─────────────────────────────────────────────────────────

export interface DecisionRecord {
    verdict: 'ALLOW' | 'DENY' | 'PROMPT';
    reasons: string[];
    verifierId: string;
    timestamp: number;
    durationMs?: number;
    webauthnUsed?: boolean;
    resolverUsed?: string;
}

export interface AlertThreshold {
    metric: string;
    warning: number;
    critical: number;
}

export interface KPISnapshot {
    windowMs: number;
    capturedAt: number;
    totalRequests: number;
    allowCount: number;
    denyCount: number;
    promptCount: number;
    denyRate: number;                    // 0-1
    allowRate: number;                   // 0-1
    securityProfileScore: number;        // 0-100 (Spec 100)
    denyCategoryBreakdown: Record<string, number>;  // Spec 65
    webauthnDriftMs?: number;            // Spec 81
    avgResolutionMs?: number;            // Spec 86-89
    estimatedCostEur?: number;           // Spec 92
    softFailActive: boolean;             // Spec 75
    alertsTriggered: string[];
}

// ─── Default Thresholds (Spec 74) ─────────────────────────────────

export const DEFAULT_ALERT_THRESHOLDS: AlertThreshold[] = [
    { metric: 'deny_rate', warning: 0.3, critical: 0.6 },
    { metric: 'prompt_rate', warning: 0.2, critical: 0.5 },
    { metric: 'allow_rate_critical', warning: 0.8, critical: 0.95 },
];

// ─── Soft-Fail Mode (Spec 75) ─────────────────────────────────────

export interface SoftFailConfig {
    enabled: boolean;
    /**
     * When soft-fail is active, DENY verdicts become PROMPT.
     * This prevents service disruption during outages.
     * NEVER use for high-risk operations.
     */
    convertDenyToPrompt: boolean;
    /** Max duration soft-fail stays active (ms) */
    maxDurationMs: number;
    activatedAt?: number;
    reason?: string;
}

export function createDefaultSoftFailConfig(): SoftFailConfig {
    return {
        enabled: false,
        convertDenyToPrompt: false,
        maxDurationMs: 30 * 60 * 1000, // 30 minutes max
    };
}

// ─── Security Profile Score (Spec 100) ─────────────────────────────

/**
 * Compute a security profile score (0-100).
 * Higher = more secure (more denies for bad requests, WebAuthn usage, etc.)
 */
export function computeSecurityScore(snapshot: Pick<KPISnapshot,
    'denyRate' | 'allowRate' | 'totalRequests' | 'webauthnDriftMs'
>): number {
    if (snapshot.totalRequests === 0) return 50; // neutral

    let score = 100;

    // Very high allow rate (>90%) is suspicious for high-assurance systems
    if (snapshot.allowRate > 0.95) score -= 20;
    else if (snapshot.allowRate > 0.9) score -= 10;

    // Very high deny rate might indicate attack or misconfiguration
    if (snapshot.denyRate > 0.8) score -= 15;

    // WebAuthn drift — stale challenges increase attack surface
    if (snapshot.webauthnDriftMs !== undefined) {
        if (snapshot.webauthnDriftMs > 60_000) score -= 10;
        else if (snapshot.webauthnDriftMs > 30_000) score -= 5;
    }

    return Math.max(0, Math.min(100, score));
}

// ─── KPI Engine ────────────────────────────────────────────────────

export class KPIEngine {
    private records: DecisionRecord[] = [];
    private softFail: SoftFailConfig = createDefaultSoftFailConfig();
    private readonly windowMs: number;
    private readonly thresholds: AlertThreshold[];

    constructor(windowMs = 5 * 60 * 1000, thresholds = DEFAULT_ALERT_THRESHOLDS) {
        this.windowMs = windowMs;
        this.thresholds = thresholds;
    }

    record(decision: DecisionRecord): void {
        this.records.push(decision);
        this.pruneOldRecords();
    }

    /**
     * Compute KPI snapshot for the current window.
     */
    snapshot(): KPISnapshot {
        this.pruneOldRecords();
        const now = Date.now();
        const total = this.records.length;

        const allowCount = this.records.filter(r => r.verdict === 'ALLOW').length;
        const denyCount = this.records.filter(r => r.verdict === 'DENY').length;
        const promptCount = this.records.filter(r => r.verdict === 'PROMPT').length;

        const denyRate = total > 0 ? denyCount / total : 0;
        const allowRate = total > 0 ? allowCount / total : 0;

        // Deny category breakdown (Spec 65)
        const denyCategoryBreakdown: Record<string, number> = {};
        for (const r of this.records.filter(r => r.verdict === 'DENY')) {
            for (const reason of r.reasons) {
                denyCategoryBreakdown[reason] = (denyCategoryBreakdown[reason] ?? 0) + 1;
            }
        }

        // Resolver metrics (Spec 86-89)
        const resolverTimes = this.records
            .filter(r => r.durationMs !== undefined)
            .map(r => r.durationMs!);
        const avgResolutionMs = resolverTimes.length > 0
            ? resolverTimes.reduce((a, b) => a + b, 0) / resolverTimes.length
            : undefined;

        // Cost estimation (Spec 92) — simplified: €0.001 per request
        const estimatedCostEur = total * 0.001;

        // Security score
        const securityProfileScore = computeSecurityScore({ denyRate, allowRate, totalRequests: total });

        // Alert check (Spec 74)
        const alertsTriggered = this.checkAlerts({ denyRate, allowRate, promptCount, total });

        // Soft-fail validity check
        const softFailActive = this.isSoftFailActive();

        return {
            windowMs: this.windowMs,
            capturedAt: now,
            totalRequests: total,
            allowCount,
            denyCount,
            promptCount,
            denyRate,
            allowRate,
            securityProfileScore,
            denyCategoryBreakdown,
            avgResolutionMs,
            estimatedCostEur,
            softFailActive,
            alertsTriggered,
        };
    }

    /**
     * Activate soft-fail mode (Spec 75).
     */
    activateSoftFail(reason: string): void {
        this.softFail = {
            ...this.softFail,
            enabled: true,
            convertDenyToPrompt: true,
            activatedAt: Date.now(),
            reason,
        };
    }

    deactivateSoftFail(): void {
        this.softFail = createDefaultSoftFailConfig();
    }

    isSoftFailActive(): boolean {
        if (!this.softFail.enabled) return false;
        const elapsed = Date.now() - (this.softFail.activatedAt ?? 0);
        return elapsed < this.softFail.maxDurationMs;
    }

    getSoftFailConfig(): SoftFailConfig {
        return { ...this.softFail };
    }

    private checkAlerts(metrics: {
        denyRate: number;
        allowRate: number;
        promptCount: number;
        total: number;
    }): string[] {
        const alerts: string[] = [];
        for (const threshold of this.thresholds) {
            let value: number | undefined;
            if (threshold.metric === 'deny_rate') value = metrics.denyRate;
            else if (threshold.metric === 'allow_rate_critical') value = metrics.allowRate;
            else if (threshold.metric === 'prompt_rate')
                value = metrics.total > 0 ? metrics.promptCount / metrics.total : 0;

            if (value === undefined) continue;
            if (value >= threshold.critical) {
                alerts.push(`CRITICAL:${threshold.metric}:${value.toFixed(2)}`);
            } else if (value >= threshold.warning) {
                alerts.push(`WARNING:${threshold.metric}:${value.toFixed(2)}`);
            }
        }
        return alerts;
    }

    private pruneOldRecords(): void {
        const cutoff = Date.now() - this.windowMs;
        this.records = this.records.filter(r => r.timestamp >= cutoff);
    }

    /** For testing */
    clearRecords(): void {
        this.records = [];
    }

    get recordCount(): number {
        return this.records.length;
    }
}
