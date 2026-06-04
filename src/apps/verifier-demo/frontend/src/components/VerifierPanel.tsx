import { useState, useEffect, useRef } from 'react';
import QRCode from 'react-qr-code';
import { ASKMI_DEMO } from '@askmi/shared-types';
import type { ScenarioDefinition } from '../data/scenarios';

interface StatusResponse {
  status: 'WAITING' | 'SCANNED' | 'VERIFIED' | 'FAILED' | 'EXPIRED';
  issuer?: string;
  verifierDid?: string;
  disclosedClaims?: Record<string, unknown>;
  consentReceipt?: { id: string; claimsShared: string[]; purpose: string; timestamp: string };
}

interface VerifierPanelProps {
  scenario: ScenarioDefinition;
  backendUrl: string;
  runNonce: number;
}

export function VerifierPanel({ scenario, backendUrl, runNonce }: VerifierPanelProps) {
  const [panelState, setPanelState] = useState<
    'waiting' | 'scanned' | 'verified' | 'failed' | 'expired' | 'offline'
  >('waiting');
  const [statusData, setStatusData] = useState<StatusResponse | null>(null);
  const lastRunNonce = useRef<number>(runNonce);

  useEffect(() => {
    lastRunNonce.current = runNonce;
    setPanelState('waiting');
    setStatusData(null);
  }, [runNonce]);

  useEffect(() => {
    let errorCount = 0;
    const MAX_CONSECUTIVE_ERRORS = 3;
    const poll = async () => {
      try {
        const res = await fetch(`${backendUrl}/status`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as StatusResponse;
        errorCount = 0;
        if (data.status === 'SCANNED') setPanelState('scanned');
        else if (data.status === 'VERIFIED') {
          setStatusData(data);
          setPanelState('verified');
        } else if (data.status === 'FAILED') {
          setStatusData(data);
          setPanelState('failed');
        } else if (data.status === 'EXPIRED') setPanelState('expired');
        else if (data.status === 'WAITING') setPanelState('waiting');
      } catch {
        errorCount++;
        if (errorCount >= MAX_CONSECUTIVE_ERRORS) setPanelState('offline');
      }
    };
    const intervalId = setInterval(poll, 1200);
    poll();
    return () => clearInterval(intervalId);
  }, [backendUrl, runNonce]);

  if (panelState === 'waiting') {
    const meta = import.meta as ImportMeta & { env?: { VITE_WALLET_URL?: string } };
    const walletBaseUrl = meta.env?.VITE_WALLET_URL ?? 'http://localhost:5174';
    const walletDeepLink = `${walletBaseUrl}/?scenario=${scenario.id}&endpoint=${encodeURIComponent(backendUrl)}&verifier=${encodeURIComponent(ASKMI_DEMO.verifierDid)}`;
    return (
      <div style={{ textAlign: 'center', padding: 24 }}>
        <QRCode value={walletDeepLink} size={160} bgColor="#ffffff" fgColor="#0a0a0a" />
        <div style={{ marginTop: 12, color: '#555', fontSize: 13 }}>
          ● Scan with wallet or open link below
        </div>
        <a
          href={walletDeepLink}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: 'block',
            marginTop: 8,
            fontSize: 10,
            color: '#0891b2',
            wordBreak: 'break-all',
            textDecoration: 'none',
          }}
        >
          Open in wallet →
        </a>
      </div>
    );
  }

  if (panelState === 'scanned') {
    return (
      <div style={{ textAlign: 'center', padding: 24 }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>📱</div>
        <div style={{ fontSize: 16, fontWeight: 700, color: '#0891b2' }}>QR Code Scanned!</div>
        <div style={{ marginTop: 8, color: '#555' }}>Waiting for user consent in wallet...</div>
        <div style={{ marginTop: 24, display: 'flex', justifyContent: 'center' }}>
          <div
            style={{
              width: 24,
              height: 24,
              border: '3px solid #0891b2',
              borderTopColor: 'transparent',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
            }}
          />
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  if (panelState === 'expired') {
    return (
      <div style={{ textAlign: 'center', padding: 24 }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>⏰</div>
        <div style={{ fontSize: 16, fontWeight: 700, color: '#b71c1c' }}>Request Expired</div>
        <div style={{ marginTop: 8, color: '#555' }}>
          The verification request has timed out for security.
        </div>
        <button
          onClick={() => fetch(`${backendUrl}/reset`, { method: 'POST' })}
          style={{
            marginTop: 20,
            padding: '10px 20px',
            background: '#0891b2',
            color: '#fff',
            border: 'none',
            borderRadius: 6,
            fontWeight: 700,
            cursor: 'pointer',
          }}
        >
          Try Again
        </button>
      </div>
    );
  }

  if (panelState === 'verified') {
    const disclosed = statusData?.disclosedClaims ?? {};
    const hasRealData = Object.keys(disclosed).length > 0;
    return (
      <div>
        {hasRealData ? (
          <>
            <div style={{ fontSize: 11, color: '#2e7d32', marginBottom: 10, fontWeight: 700 }}>
              ✅ Cryptographically verified claims:
            </div>
            {Object.entries(disclosed).map(([key, value]) => (
              <div
                key={key}
                style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}
              >
                <span style={{ color: '#2e7d32', fontWeight: 700 }}>✅</span>
                <span style={{ color: '#81c784', fontFamily: 'monospace', fontSize: 13 }}>
                  {key}: {String(value)}
                </span>
              </div>
            ))}
          </>
        ) : (
          scenario.verifierReceives.map((claim) => (
            <div
              key={claim.key}
              style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}
            >
              <span style={{ color: '#2e7d32', fontWeight: 700 }}>✅</span>
              <span style={{ color: '#81c784', fontFamily: 'monospace', fontSize: 13 }}>
                {claim.key}: {claim.isProof ? <em>proof only</em> : claim.value}
              </span>
            </div>
          ))
        )}
        {scenario.blocked.map((field) => (
          <div
            key={field}
            style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}
          >
            <span style={{ color: '#b71c1c', fontWeight: 700 }}>❌</span>
            <span style={{ color: '#555', fontFamily: 'monospace', fontSize: 13 }}>
              {field}: <span style={{ color: '#333' }}>[NOT RECEIVED]</span>
            </span>
          </div>
        ))}
        <div
          style={{
            marginTop: 16,
            padding: '8px 12px',
            background: '#0a1a0a',
            borderRadius: 8,
            fontSize: 11,
            color: '#2e7d32',
            fontFamily: 'monospace',
          }}
        >
          🔐 Session keys shredded — W-05 cleanup complete
        </div>
      </div>
    );
  }

  if (panelState === 'failed') {
    return (
      <div
        style={{
          background: '#1a0505',
          padding: 16,
          borderRadius: 10,
          borderLeft: '3px solid #b71c1c',
          color: '#ef9a9a',
          fontSize: 14,
        }}
      >
        ⛔ Verification failed or credential denied
        {scenario.id === 'revoked' && (
          <div style={{ marginTop: 8, fontSize: 11, color: '#b71c1c', fontFamily: 'monospace' }}>
            Reason: Credential revoked (status_list check)
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ textAlign: 'center', padding: 24, color: '#555' }}>
      <div style={{ fontSize: 32, marginBottom: 8 }}>⚡</div>
      <div style={{ fontSize: 13, marginBottom: 4 }}>Backend offline</div>
    </div>
  );
}
