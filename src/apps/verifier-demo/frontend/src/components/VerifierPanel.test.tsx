import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { ASKMI_DEMO } from '@askmi/shared-types';
import { VerifierPanel } from './VerifierPanel';
import { SCENARIOS, SCENARIO_ORDER } from '../data/scenarios';

describe('VerifierPanel G-110.1 handoff affordance', () => {
  it.each(SCENARIO_ORDER)('renders QR and Open in Wallet link for %s', (scenarioId) => {
    const backendUrl = 'http://localhost:3004';
    const sessionId = 'flow-session-123';
    const html = renderToStaticMarkup(
      <VerifierPanel scenario={SCENARIOS[scenarioId]} backendUrl={backendUrl} sessionId={sessionId} runNonce={1} />
    );

    expect(html).toContain('<svg');
    expect(html).toContain('Open in wallet');

    const encodedEndpoint = encodeURIComponent(backendUrl);
    const encodedVerifier = encodeURIComponent(ASKMI_DEMO.verifierDid);
    expect(html).toContain(`scenario=${scenarioId}`);
    expect(html).toContain(`endpoint=${encodedEndpoint}`);
    expect(html).toContain(`verifier=${encodedVerifier}`);
    expect(html).toContain(`sessionId=${sessionId}`);
  });
});
