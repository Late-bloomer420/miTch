import { useEffect, useRef, useState } from 'react';
import QRCode from 'react-qr-code';

type Session = {
  sessionId: string;
  status: string;
  result?: { eligible: boolean };
  handoff?: { url: string };
};

export function ConnectPanel({ backendUrl }: { backendUrl: string }) {
  const [session, setSession] = useState<Session | null>(null);
  const [handoff, setHandoff] = useState('');
  const [error, setError] = useState('');
  const [starting, setStarting] = useState(false);
  const generation = useRef(0);
  const pending = session?.status === 'pending' || session?.status === 'wallet_opened';

  async function start() {
    const attempt = ++generation.current;
    setStarting(true);
    setError('');
    setSession(null);
    setHandoff('');
    try {
      const response = await fetch(`${backendUrl}/askmi/connect/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policyId: 'age-liquor-store-v1' }),
      });
      if (!response.ok) throw new Error('Could not start verification. Please try again.');
      const created = (await response.json()) as Session;
      if (!created.sessionId || !created.handoff?.url || created.status !== 'pending')
        throw new Error('Invalid session response.');
      if (generation.current === attempt) {
        setSession(created);
        setHandoff(created.handoff.url);
      }
    } catch (cause) {
      if (generation.current === attempt)
        setError(cause instanceof Error ? cause.message : 'Verification unavailable.');
    } finally {
      if (generation.current === attempt) setStarting(false);
    }
  }

  useEffect(() => {
    if (!session || !pending) return;
    let active = true;
    const attempt = generation.current;
    const id = session.sessionId;
    const poll = async () => {
      try {
        const response = await fetch(
          `${backendUrl}/askmi/connect/sessions/${encodeURIComponent(id)}`,
          { cache: 'no-store' }
        );
        if (!response.ok) throw new Error('Status unavailable. Start a new verification.');
        const status = (await response.json()) as Session;
        if (active && generation.current === attempt) {
          setSession(status);
          setError('');
        }
      } catch {
        if (active && generation.current === attempt)
          setError('Status unavailable. No verification result is confirmed.');
      }
    };
    const interval = setInterval(() => {
      void poll();
    }, 1200);
    void poll();
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [backendUrl, session?.sessionId, pending]);

  return (
    <main style={{ maxWidth: 560, margin: '48px auto', padding: 24, fontFamily: 'system-ui' }}>
      <a href="?">Back to simulated demo</a>
      <h1>Verify age with your wallet</h1>
      <p>
        The verifier checks numeric age from your credential and returns whether you are 18 or
        older. Numeric age is omitted from the application result and session status.
      </p>
      {error && <p role="alert">{error}</p>}
      {pending && handoff && (
        <>
          <QRCode value={handoff} size={180} />
          <p>
            <a href={handoff} target="_blank" rel="noopener noreferrer">
              Open in wallet
            </a>
          </p>
          <p>
            {session?.status === 'wallet_opened'
              ? 'Waiting for your wallet response.'
              : 'Scan the code or open your wallet.'}
          </p>
        </>
      )}
      {session?.status === 'verified' && session.result?.eligible === true && (
        <p role="status">Age eligibility confirmed (18+).</p>
      )}
      {(session?.status === 'failed' || session?.status === 'expired') && (
        <p role="status">Verification {session.status}. Start a new session to retry.</p>
      )}
      <button disabled={starting || (pending && !error)} onClick={() => void start()}>
        {starting ? 'Starting…' : 'Start age verification'}
      </button>
    </main>
  );
}
