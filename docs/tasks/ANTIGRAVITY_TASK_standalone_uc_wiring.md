# Antigravity Task: Wire Use Cases to Interactive Demo

**Datei:** `src/packages/poc-hardened/src/poc-web/standalone.html` (4293 Zeilen, alles-in-einer-Datei)
**Branch:** `master`, conventional commits: `feat(standalone): ...`
**Regel:** Kein externer Build, kein Framework — bleibt eine self-contained HTML-Datei.

---

## Problem

Die standalone.html hat zwei getrennte Welten die nicht miteinander reden:

1. **Use Case Showcase** (Zeile ~1730-2100): 5 Tabs (Ad-Tech, Student, Hospital, EHDS, Social Login) mit jeweils Step-by-Step Walkthrough und eigenem `ucRunProof()` / `ucRunStudentProof()` etc.

2. **Interactive Demo** (Zeile ~2230-2450): Issue Credential → Wallet Claims → Policy Engine → Verifier → Crypto-Shred. Läuft IMMER als "CoolShop.at Age Verification" mit hardcoded `CLAIMS = { over_18, over_16, over_21, email_verified, jurisdiction }`.

3. **Cost Comparison** (Zeile ~3660-3810): Zeigt generische Identity-Kosten, updated sich nur bei Issuance/Verification — aber ohne Bezug zum gewählten Use Case.

**→ User kann sich keinen Use Case aussuchen und dann den vollen Demo-Flow damit durchspielen.**

---

## Ziel

Wenn der User einen Use Case wählt, soll die gesamte Demo sich anpassen:
- Andere **Verifier-Identität** (nicht immer CoolShop.at)
- Andere **Claims** (pre-selected, passend zum Use Case)
- Andere **Policy Engine Logik** (verschiedene Verdicts)
- Andere **Cost Comparison Zahlen** (Use-Case-spezifisch)
- Andere **Audit Log Einträge**

Der User Flow soll sein:
1. Use Case Tab auswählen (oder "Try in Demo →" Button im Use Case Walkthrough)
2. Demo-Bereich scrollt rein / updated sich
3. Credential wird mit passenden Claims issued
4. Verification läuft mit Use-Case-spezifischem Verifier + Policy
5. Costs zeigen Use-Case-relevante Zahlen

---

## Architektur-Änderung

### 1. Scenario-Config Objekt (NEU)

Ersetze den hardcoded `CLAIMS` und `CoolShop.at` durch ein Scenario-System:

```javascript
const SCENARIOS = {
  adtech: {
    name: 'Ad-Tech Blind Provider',
    verifier: { name: 'AdNetwork GmbH', did: 'did:mitch:adnetwork-gmbh' },
    claims: {
      nullifier: 'H(…a8f3c201)',        // generated
      budget_slot: 'slot_742 (1/1920)', // generated
      cohort_signal: 'interest_group_17',
    },
    // Which claims are auto-selected vs optional
    required: ['nullifier', 'budget_slot'],
    optional: ['cohort_signal'],
    // Policy Engine behavior
    policy: {
      rule: 'ad_verification',
      verdict: 'ALLOW',           // always auto-approve (zero PII)
      reason: 'Zero PII disclosed — deterministic verification only',
      checks: [
        '🔍 Verifier identity check (did:mitch:adnetwork-gmbh)',
        '📋 Matching policy rule: "ad_blind_provider" → AdNetwork GmbH',
        '📊 Claims requested: nullifier, budget_slot (zero PII)',
        '🛡️ Data minimization: PASS — no personal data leaves device',
        '✅ Deterministic proof, no PII → ALLOW (auto-approve)',
      ],
    },
    // Cost comparison overrides
    costs: {
      traditional: {
        label: 'Programmatic Ad (Traditional)',
        items: [
          { label: 'Third-party cookie tracking', avg: 0.35, source: 'Industry avg CPM' },
          { label: 'Cross-site fingerprinting', avg: 0.08, source: 'FLoC/Topics API alternative' },
          { label: 'Data broker enrichment', avg: 0.15, source: 'Oracle/Lotame pricing' },
          { label: 'GDPR consent banner', avg: 0.04, source: 'OneTrust enterprise' },
          { label: 'Regulatory risk reserve', avg: 0.12, source: 'Average GDPR fine ÷ impressions' },
        ],
      },
      mitch: {
        label: 'miTch Blind Provider',
        items: [
          { label: 'Nullifier generation (on-device)', avg: 0, source: 'WebCrypto — free' },
          { label: 'Budget signal (quantized)', avg: 0, source: 'Local computation — free' },
          { label: 'StatusList CDN check', avg: 0.0003, source: 'CloudFront bitstring' },
          { label: 'PII stored', avg: 0, source: 'Zero — crypto-shredded' },
        ],
      },
      scaleNote: 'Bei 10M Impressions/Monat',
    },
  },

  student: {
    name: 'Invisible Student',
    verifier: { name: 'IVB Innsbruck', did: 'did:mitch:ivb-innsbruck' },
    claims: {
      is_student: true,
      semester_valid_until: '2026-09-30',
    },
    required: ['is_student'],
    optional: ['semester_valid_until'],
    policy: {
      rule: 'student_discount',
      verdict: 'ALLOW',
      reason: 'Boolean predicate only — no identity data disclosed',
      checks: [
        '🔍 Verifier identity check (did:mitch:ivb-innsbruck)',
        '📋 Matching policy rule: "student_discount" → IVB Innsbruck',
        '📊 Claims requested: is_student (boolean), semester_valid_until',
        '🛡️ Data minimization: PASS — no name, no Matrikelnummer',
        '✅ Boolean predicate, trusted municipal verifier → ALLOW',
      ],
    },
    costs: {
      traditional: {
        label: 'Student Verification (Traditional)',
        items: [
          { label: 'Physical ID check at counter', avg: 2.50, source: 'Staff cost per verification' },
          { label: 'Student ID card production', avg: 5.00, source: 'ÖH Ausweis annual cost' },
          { label: 'Database integration (Uni↔IVB)', avg: 0.80, source: 'API maintenance/year ÷ verifications' },
          { label: 'PII storage (name, Matrikelnr.)', avg: 0.03, source: 'GDPR-compliant DB hosting' },
          { label: 'Manual fraud checks', avg: 0.50, source: 'Spot-check staff allocation' },
        ],
      },
      mitch: {
        label: 'miTch Invisible Student',
        items: [
          { label: 'SD-JWT boolean proof', avg: 0, source: 'On-device selective disclosure' },
          { label: 'Semester validity check', avg: 0.0003, source: 'StatusList CDN' },
          { label: 'Student ID card needed', avg: 0, source: 'Not needed — wallet proof' },
          { label: 'PII stored by IVB', avg: 0, source: 'Zero — only boolean received' },
        ],
      },
      scaleNote: 'Bei 50.000 Studenten/Jahr in Innsbruck',
    },
  },

  hospital: {
    name: 'Hospital Admission',
    verifier: { name: 'Tirol Kliniken GmbH', did: 'did:mitch:tirol-kliniken' },
    claims: {
      full_name: 'Maria Musterfrau',
      date_of_birth: '1995-03-15',
      insurance_id: 'AT-SVS-1234567',
      blood_type: 'A+',
      allergies: 'Penicillin',
      emergency_contact: '+43 660 1234567',
    },
    required: ['full_name', 'date_of_birth', 'insurance_id'],
    optional: ['blood_type', 'allergies', 'emergency_contact'],
    policy: {
      rule: 'medical_admission',
      verdict: 'PROMPT',
      reason: 'Sensitive medical + identity data — explicit consent required',
      checks: [
        '🔍 Verifier identity check (did:mitch:tirol-kliniken)',
        '📋 Matching policy rule: "medical_admission" → Tirol Kliniken',
        '📊 Claims requested: 6 attributes including medical data',
        '🛡️ Data minimization: WARNING — blood_type + allergies are sensitive',
        '⚠️ Multiple sensitive claims → PROMPT (explicit consent required)',
      ],
    },
    costs: {
      traditional: {
        label: 'Hospital Admission (Traditional)',
        items: [
          { label: 'Manual registration (reception staff)', avg: 8.00, source: '~15min × €32/hr' },
          { label: 'Insurance verification API', avg: 0.50, source: 'SV-GKK/ÖGK interface' },
          { label: 'Paper form digitization', avg: 1.20, source: 'Scanning + OCR pipeline' },
          { label: 'EHR data entry', avg: 3.00, source: 'Manual entry time' },
          { label: 'ELGA integration', avg: 0.30, source: 'ELGA GmbH transaction fee' },
          { label: 'Data breach risk (medical)', avg: 0.45, source: 'IBM 2024: healthcare €10.93M avg' },
        ],
      },
      mitch: {
        label: 'miTch Hospital Admission',
        items: [
          { label: 'Verifiable Credential presentation', avg: 0, source: 'On-device, instant' },
          { label: 'Insurance status proof', avg: 0.01, source: 'Issuer-signed, no API call' },
          { label: 'Consent + audit trail', avg: 0, source: 'Built into wallet flow' },
          { label: 'ELGA bridge (future)', avg: 0.05, source: 'Estimated FHIR adapter cost' },
          { label: 'Breach risk reduction', avg: 0.02, source: 'Minimal PII retained post-admission' },
        ],
      },
      scaleNote: 'Bei 500.000 Aufnahmen/Jahr in Tirol',
    },
  },

  ehds: {
    name: 'EHDS Research Access',
    verifier: { name: 'EU Health Research Portal', did: 'did:mitch:ehds-portal' },
    claims: {
      health_record_pseudonymized: '[encrypted blob]',
      data_category: 'cardiovascular',
      consent_scope: 'research_only',
      retention_limit: '24_months',
    },
    required: ['consent_scope', 'data_category'],
    optional: ['health_record_pseudonymized', 'retention_limit'],
    policy: {
      rule: 'ehds_secondary_use',
      verdict: 'DENY',
      reason: 'Secondary health data use requires explicit Art. 9 consent + ethics board approval',
      checks: [
        '🔍 Verifier identity check (did:mitch:ehds-portal)',
        '📋 Matching policy rule: "ehds_secondary_use" → EU Research Portal',
        '📊 Claims requested: pseudonymized health record (Art. 9 GDPR)',
        '🛡️ Data minimization: FAIL — health data requires highest protection',
        '⛔ Art. 9 special category data, no ethics approval attached → DENY',
      ],
      // EHDS has break-glass override
      hasBreakGlass: true,
      breakGlassChecks: [
        '🔓 Break-Glass activated — emergency research override',
        '📋 Logging elevated access to immutable audit chain',
        '⏰ Auto-expiry set: 24 hours',
        '⚠️ OVERRIDE: ALLOW with mandatory audit trail',
      ],
    },
    costs: {
      traditional: {
        label: 'Health Data Research (Traditional)',
        items: [
          { label: 'Ethics board application', avg: 15.00, source: 'Per-study cost amortized' },
          { label: 'Data anonymization service', avg: 3.50, source: 'K-anonymity/l-diversity processing' },
          { label: 'Secure data room access', avg: 2.00, source: 'Trusted Research Environment' },
          { label: 'Re-identification risk insurance', avg: 1.50, source: 'Specialized cyber insurance' },
          { label: 'Cross-border transfer (EDPB)', avg: 0.80, source: 'Legal review per jurisdiction' },
        ],
      },
      mitch: {
        label: 'miTch EHDS Access',
        items: [
          { label: 'Pseudonymized data proof', avg: 0.05, source: 'ZK proof generation (estimated)' },
          { label: 'Consent verification', avg: 0, source: 'On-chain consent record' },
          { label: 'Automatic audit trail', avg: 0.01, source: 'Transparency log entry' },
          { label: 'Re-identification risk', avg: 0, source: 'Crypto-shredding prevents re-ID' },
        ],
      },
      scaleNote: 'Bei 100.000 Forschungszugriffen/Jahr EU-weit',
    },
  },

  social: {
    name: 'Social Login (Pseudonymous)',
    verifier: { name: 'FlirtRadar.app', did: 'did:mitch:flirtradar' },
    claims: {
      pseudonym_id: 'nym_' + 'a8f3c201',  // deterministic per-site
      age_range: '18-25',
      is_human: true,
    },
    required: ['pseudonym_id', 'is_human'],
    optional: ['age_range'],
    policy: {
      rule: 'social_login_pseudonymous',
      verdict: 'ALLOW',
      reason: 'Pseudonymous login — no real identity data disclosed',
      checks: [
        '🔍 Verifier identity check (did:mitch:flirtradar)',
        '📋 Matching policy rule: "social_login" → FlirtRadar.app',
        '📊 Claims requested: pseudonym, age_range, is_human (zero PII)',
        '🛡️ Data minimization: PASS — site-specific pseudonym, no linkability',
        '✅ Pseudonymous claims only → ALLOW (auto-approve)',
      ],
    },
    costs: {
      traditional: {
        label: 'Social Login (Traditional)',
        items: [
          { label: 'OAuth provider (Google/Facebook)', avg: 0, source: 'Free — but you ARE the product' },
          { label: 'Profile data harvesting (hidden cost)', avg: 0.25, source: 'User data value to ad networks' },
          { label: 'Cross-site tracking (shadow profile)', avg: 0.15, source: 'Aggregate profiling value' },
          { label: 'Account takeover risk', avg: 0.08, source: 'Credential stuffing losses amortized' },
          { label: 'GDPR consent (cookie banners)', avg: 0.04, source: 'CMP integration' },
        ],
      },
      mitch: {
        label: 'miTch Pseudonymous Login',
        items: [
          { label: 'Pseudonym generation (on-device)', avg: 0, source: 'HKDF derivation — free' },
          { label: 'Humanity proof', avg: 0, source: 'Local WebAuthn — free' },
          { label: 'Profile data shared', avg: 0, source: 'Zero — pseudonym only' },
          { label: 'Cross-site linkability', avg: 0, source: 'Impossible — pairwise pseudonyms' },
        ],
      },
      scaleNote: 'Bei 1M Logins/Monat',
    },
  },
};
```

### 2. Active Scenario State

```javascript
let activeScenario = null; // key from SCENARIOS

function activateScenario(key) {
  activeScenario = key;
  const sc = SCENARIOS[key];

  // 1. Update CLAIMS object to match scenario
  // Clear old claims, populate new ones
  Object.keys(CLAIMS).forEach(k => delete CLAIMS[k]);
  Object.assign(CLAIMS, sc.claims);

  // 2. Update claim checkboxes in wallet panel
  rebuildClaimCheckboxes(sc);

  // 3. Update verifier name everywhere
  updateVerifierName(sc.verifier.name, sc.verifier.did);

  // 4. Pre-select required claims, leave optional unchecked
  sc.required.forEach(k => {
    const el = document.getElementById('c-' + k);
    if (el) { el.checked = true; el.disabled = true; } // required = locked
  });

  // 5. Reset demo state + scroll to demo section
  doReset();
  scrollToDemo();

  // 6. Visual indicator: which scenario is active
  document.querySelectorAll('.uc-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.uc === key));
}
```

### 3. Policy Engine Anpassung

Die `startVerification()` Funktion (Zeile ~3359) muss das Scenario nutzen:

```javascript
async function startVerification() {
  const sc = activeScenario ? SCENARIOS[activeScenario] : null;

  // ... existing claim selection code ...

  const engineChecks = sc
    ? sc.policy.checks  // Use scenario-specific checks
    : [/* existing fallback checks */];

  const verdict = STATE.revoked ? 'DENY (revoked)'
    : sc ? sc.policy.verdict
    : (needsConsent ? 'PROMPT' : 'ALLOW');

  // ... rest of engine animation ...

  // EHDS break-glass special handling
  if (sc?.policy.hasBreakGlass && verdict === 'DENY') {
    showBreakGlassOption(sc);
  }
}
```

### 4. Cost Comparison Anpassung

Die `renderCosts()` Funktion (Zeile ~3700) muss Scenario-Costs nutzen:

```javascript
function renderCosts(phase) {
  const sc = activeScenario ? SCENARIOS[activeScenario] : null;

  if (sc?.costs) {
    // Render scenario-specific costs instead of generic ones
    renderScenarioCosts(sc.costs);
    return;
  }

  // ... existing generic cost rendering as fallback ...
}

function renderScenarioCosts(costs) {
  document.getElementById('cost-ph').style.display = 'none';
  document.getElementById('cost-result').style.display = 'block';

  const tradTotal = costs.traditional.items.reduce((s, i) => s + i.avg, 0);
  const mitchTotal = costs.mitch.items.reduce((s, i) => s + i.avg, 0);
  const savingsPct = tradTotal > 0 ? ((1 - mitchTotal / tradTotal) * 100).toFixed(0) : '100';

  // Render items lists
  document.getElementById('cost-traditional').innerHTML = costs.traditional.items.map(i =>
    `<li style="..."><span>${i.label}</span><span style="color:var(--red)">€${i.avg.toFixed(3)}</span></li>`
  ).join('');

  document.getElementById('cost-mitch').innerHTML = costs.mitch.items.map(i =>
    `<li style="..."><span>${i.label}</span><span style="color:${i.avg === 0 ? 'var(--green)' : 'var(--yellow)'}">
      ${i.avg === 0 ? '€0.000 ✅' : '€' + i.avg.toFixed(3)}</span></li>`
  ).join('');

  // Headers
  document.getElementById('cost-trad-total').innerHTML =
    `<span class="dim">${costs.traditional.label}:</span> <span style="color:var(--red)">€${tradTotal.toFixed(3)}</span>`;
  document.getElementById('cost-mitch-total').innerHTML =
    `<span class="dim">${costs.mitch.label}:</span> <span style="color:var(--green)">€${mitchTotal.toFixed(3)}</span>`;

  // Scale note
  document.getElementById('cost-savings').innerHTML = `
    <div style="...">
      ${savingsPct}% savings — ${costs.scaleNote}
    </div>`;

  // Sources
  const allSources = [...costs.traditional.items, ...costs.mitch.items].map(i => i.source).filter(Boolean);
  document.getElementById('cost-sources').innerHTML = '📎 ' + [...new Set(allSources)].join(' · ');
}
```

### 5. "Try in Demo →" Bridge Button

In jedem Use Case Walkthrough (letzer Step) einen Button einfügen:

```html
<!-- Inside each UC pane's last step -->
<button class="btn btn-primary" onclick="activateScenario('adtech')"
  style="margin-top:1rem; width:100%">
  🚀 Try this in the Interactive Demo →
</button>
```

Für jeden Use Case den passenden Key: `'adtech'`, `'student'`, `'hospital'`, `'ehds'`, `'social'`.

### 6. Wallet Claim Checkboxes dynamisch bauen

```javascript
function rebuildClaimCheckboxes(sc) {
  const container = document.getElementById('wallet-claims'); // existing checkbox area
  container.innerHTML = '';

  Object.entries(sc.claims).forEach(([key, value]) => {
    const isRequired = sc.required.includes(key);
    const displayValue = typeof value === 'boolean' ? (value ? '✅' : '❌')
      : typeof value === 'string' && value.length > 20 ? value.substring(0, 20) + '…'
      : value;

    container.innerHTML += `
      <label class="claim-row" style="display:flex;align-items:center;gap:0.5rem;padding:0.3rem 0">
        <input type="checkbox" id="c-${key}"
          ${isRequired ? 'checked disabled' : ''}
          ${sc.optional.includes(key) ? '' : 'checked'}>
        <span class="k">${key}:</span>
        <span class="${isRequired ? 'vt' : 'vs'}">${displayValue}</span>
        ${isRequired ? '<span class="tag tag-blue" style="font-size:0.6rem">required</span>' : ''}
      </label>`;
  });
}
```

### 7. Verifier Name Update

```javascript
function updateVerifierName(name, did) {
  // Update all hardcoded "CoolShop.at" references in the demo panels
  // The consent reason text, audit entries, verifier panel header, etc.
  STATE.verifierName = name;
  STATE.verifierDid = did;

  // Update verifier panel header if it exists
  const verifierHeader = document.querySelector('#p-verifier .ph');
  if (verifierHeader) {
    // Keep icon, update text
  }
}
```

Dann in `startVerification()`, `doApprove()`, `doReject()`, `completeVerification()` etc.:
- Ersetze alle hardcoded `'CoolShop.at'` durch `STATE.verifierName || 'CoolShop.at'`
- Ersetze alle hardcoded `'did:mitch:verifier-coolshop'` durch `STATE.verifierDid || 'did:mitch:verifier-coolshop'`

---

## UI/UX Anforderungen

1. **Scenario Indicator**: Wenn ein Scenario aktiv ist, zeige oben im Demo-Bereich ein kleines Badge: `🎓 Student Discount Demo` (farblich passend zum Use Case)

2. **Smooth Transition**: `activateScenario()` soll smooth zum Demo-Bereich scrollen (wie `switchUC()` bereits smooth scrollt)

3. **Default Scenario**: Ohne Auswahl bleibt der alte "CoolShop.at" Flow als Fallback (backwards compatible)

4. **EHDS Break-Glass**: Bei EHDS ist der Verdict DENY. Zeige einen "🔓 Emergency Override" Button der den Break-Glass Flow triggert (bereits als `ucRunBreakGlass()` in den UC-Panels vorhanden — Logik wiederverwenden)

5. **Visual Consistency**: Die Scenario-spezifischen Costs sollen das gleiche Layout nutzen wie die bestehende Cost Comparison (Side-by-side Traditional vs miTch, rote vs grüne Zahlen, Savings-Box unten)

6. **Confetti**: Behalte den Confetti-Burst bei successful verification bei ✨

7. **Mobile**: Muss auf iPad funktionieren (Jonas testet dort)

---

## Dateien die geändert werden

NUR `src/packages/poc-hardened/src/poc-web/standalone.html`:

1. `SCENARIOS` Objekt einfügen (nach `CLAIMS` Definition, ~Zeile 2996)
2. `activateScenario()`, `rebuildClaimCheckboxes()`, `updateVerifierName()`, `renderScenarioCosts()` Funktionen
3. `startVerification()` erweitern (Scenario-aware Policy Checks)
4. `renderCosts()` erweitern (Scenario-aware Costs)
5. `completeVerification()` → `STATE.verifierName` statt hardcoded
6. "Try in Demo →" Buttons in jeden UC-Pane letzten Step
7. Scenario Badge UI Element im Demo-Header
8. `doReset()` → `activeScenario = null` + Badge entfernen

---

## Was NICHT ändern

- Bestehende UC Step-by-Step Walkthroughs (die bleiben wie sie sind)
- WebAuthn/Passkey Flow (funktioniert unabhängig vom Scenario)
- Audit Chain / Consent Log Struktur
- Revocation Feature
- CSS Theme Toggle
- Kein Build-System, keine externen Deps

---

## Test-Checklist

- [ ] Seite lädt ohne Errors (Konsole clean)
- [ ] Ohne Scenario-Auswahl: alter CoolShop.at Flow funktioniert wie bisher
- [ ] Jeder der 5 Use Cases: Tab klicken → "Try in Demo →" → Demo passt sich an
- [ ] Ad-Tech: ALLOW verdict, nullifier-basierte Claims, Ad-spezifische Costs
- [ ] Student: ALLOW verdict, boolean Claims, IVB Costs
- [ ] Hospital: PROMPT verdict, Consent-Modal erscheint, medizinische Claims
- [ ] EHDS: DENY verdict, Break-Glass Option, Forschungs-Costs
- [ ] Social Login: ALLOW verdict, Pseudonym Claims, Social Login Costs
- [ ] Cost Comparison updated sich korrekt pro Scenario
- [ ] Reset setzt auf Default zurück
- [ ] Funktioniert auf iPad Safari
- [ ] Confetti noch da 🎉
