export interface TrackingPoint {
    layer: 'OS' | 'NETWORK' | 'BROWSER' | 'SERVER' | 'SDK';
    actor: string;
    dataExposed: {
        field: string;
        visibility: 'PLAINTEXT' | 'HASHED' | 'ENCRYPTED';
        linkable: boolean;
        persistence: 'SESSION' | 'DEVICE' | 'CLOUD';
    }[];
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
    riskReason: string;
    detection: {
        method: 'HEURISTIC' | 'ACTIVE_TEST' | 'PRIVACY_POLICY' | 'CVE';
        confidence: number;
        source?: string;
    };
    mitigations: {
        type: 'VPN' | 'TOR' | 'APP_SETTING' | 'DEGOOGLED' | 'ACCEPT_RISK';
        label: string;
        effectiveness: number;
        cost: 'FREE' | 'PAID' | 'HIGH_EFFORT';
        implementation: {
            automaticOption?: boolean;
            link?: string;
        };
    }[];
}

export interface PrivacyContext {
    transactionId: string;
    verifier: string;
    detectedTrackers: TrackingPoint[];
    privacyScore: {
        overall: number;
        breakdown: {
            os_risk: number;
            network_risk: number;
            browser_risk: number;
        };
    };
    userConsent: {
        status: 'EXPLICIT_ACCEPT' | 'REJECT' | 'CONDITIONAL_ACCEPT';
        timestamp: string;
        conditions?: {
            acceptTrackingBy: string[];
            requireVPN: boolean;
        };
    };
    auditProof: {
        hash: string;
        signature: string;
    };
}

export interface PrivacyConsent {
    status: 'ACCEPT';
    acceptedTrackers: string[];
    timestamp: string;
    auditHash: string;
}


// Mock Service Implementation
export class PrivacyAuditService {
    static async auditTransaction(verifierName: string): Promise<PrivacyContext> {
        // Simulate async detection
        await new Promise(resolve => setTimeout(resolve, 800));

        const userAgent = navigator.userAgent;
        const trackers: TrackingPoint[] = [];

        // 1. OS Detection
        if (userAgent.includes('Android')) {
            trackers.push({
                layer: 'OS',
                actor: 'Google (Android OS)',
                riskLevel: 'HIGH',
                riskReason: 'OS-level telemetry active',
                dataExposed: [
                    { field: 'Advertising ID', visibility: 'PLAINTEXT', linkable: true, persistence: 'DEVICE' },
                    { field: 'App Usage Stats', visibility: 'ENCRYPTED', linkable: true, persistence: 'CLOUD' }
                ],
                detection: { method: 'HEURISTIC', confidence: 95, source: 'UserAgent' },
                mitigations: [
                    { type: 'DEGOOGLED', label: 'Switch to GrapheneOS', effectiveness: 100, cost: 'HIGH_EFFORT', implementation: { link: 'https://grapheneos.org' } }
                ]
            });
        } else if (userAgent.includes('iPhone') || userAgent.includes('Mac')) {
            trackers.push({
                layer: 'OS',
                actor: 'Apple',
                riskLevel: 'MEDIUM',
                riskReason: 'Apple ID telemetry',
                dataExposed: [
                    { field: 'Device Serial (Hash)', visibility: 'HASHED', linkable: true, persistence: 'CLOUD' }
                ],
                detection: { method: 'HEURISTIC', confidence: 90 },
                mitigations: []
            });
        } else if (userAgent.includes('Windows')) {
            trackers.push({
                layer: 'OS',
                actor: 'Microsoft',
                riskLevel: 'MEDIUM',
                riskReason: 'Windows Telemetry',
                dataExposed: [
                    { field: 'Diagnostic Data', visibility: 'ENCRYPTED', linkable: true, persistence: 'CLOUD' }
                ],
                detection: { method: 'HEURISTIC', confidence: 85 },
                mitigations: []
            });
        }

        // 2. Browser Detection
        if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) {
            trackers.push({
                layer: 'BROWSER',
                actor: 'Google Chrome',
                riskLevel: 'HIGH',
                riskReason: 'Chrome Sync & FLoC/Topics',
                dataExposed: [
                    { field: 'Browsing History', visibility: 'ENCRYPTED', linkable: true, persistence: 'CLOUD' }
                ],
                detection: { method: 'HEURISTIC', confidence: 99 },
                mitigations: [
                    { type: 'APP_SETTING', label: 'Use Firefox / Brave', effectiveness: 90, cost: 'FREE', implementation: { link: 'https://mozilla.org' } }
                ]
            });
        }

        // 3. Network / ISP (Mocked)
        trackers.push({
            layer: 'NETWORK',
            actor: 'Unknown ISP',
            riskLevel: 'MEDIUM',
            riskReason: 'DNS Queries visible to ISP',
            dataExposed: [
                { field: 'DNS Request (Verifier Domain)', visibility: 'PLAINTEXT', linkable: false, persistence: 'SESSION' },
                { field: 'Source IP', visibility: 'PLAINTEXT', linkable: true, persistence: 'SESSION' }
            ],
            detection: { method: 'HEURISTIC', confidence: 60, source: 'No VPN Detected' },
            mitigations: [
                { type: 'VPN', label: 'Enable VPN', effectiveness: 95, cost: 'PAID', implementation: { automaticOption: true, link: 'https://mullvad.net' } }
            ]
        });

        const overallScore = Math.max(0, 100 - trackers.reduce((sum, t) => sum + (t.riskLevel === 'HIGH' ? 40 : t.riskLevel === 'MEDIUM' ? 20 : 5), 0));

        return {
            transactionId: crypto.randomUUID(),
            verifier: verifierName,
            detectedTrackers: trackers,
            privacyScore: {
                overall: overallScore,
                breakdown: { os_risk: 30, network_risk: 20, browser_risk: 10 } // simplified
            },
            userConsent: {
                status: 'CONDITIONAL_ACCEPT',
                timestamp: new Date().toISOString()
            },
            auditProof: {
                hash: Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join(''),
                signature: 'mock_sig'
            }
        };
    }
}
