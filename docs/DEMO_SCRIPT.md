# miTch Live Demo Script
**Zielgruppe:** Uni-Präsentation, technisch-informiertes Publikum
**Dauer:** 8–12 Min Demo + Fragen
**Setup-Zeit:** 5 Min vorher

---

## Voraussetzungen

```bash
# 1. Repo klonen und installieren
git clone https://github.com/Late-bloomer420/miTch.git
cd miTch
pnpm install

# 2. Alle Services starten (drei Terminals)
pnpm dev
# Startet parallel:
#   wallet-pwa      → http://localhost:5174
#   issuer-mock     → http://localhost:3005
#   verifier-demo   → http://localhost:3004

# 3. Sanity Check: Tests müssen grün sein
pnpm test
# Erwartete Ausgabe: 38/38 tasks, 751+ tests passed
```

**Browser:** Chrome/Firefox, DevTools offen auf Console-Tab.

---

## Szenario 1 — Liquor Store (Altersverifikation) 🍺

**Narrative:** "Alice, 25 Jahre alt, kauft online Wein. Der Shop fragt nach Altersverifikation. Sie teilt NUR den Beweis 'Alter ≥ 18' — kein Geburtsdatum, kein Name."

### Schritte
1. Browser öffnen: `http://localhost:5174`
2. Wallet lädt — "Age Credential" ist bereits vorhanden (Gov Issuer)
3. Auf **"🍺 Liquor Store (18+)"** klicken
4. Policy Engine evaluiert — Consent Sheet erscheint
5. **Was der Zuschauer sieht:**
   - Grünes "Low Risk"-Banner
   - Claims-Chip: `✅ age >= 18` (ZKP — kein Rohdatum!)
   - Kein Name, kein Geburtsdatum in der Disclosure
6. **"✅ Approve Disclosure"** klicken
7. Console zeigt: `Pairwise DID: did:peer:0z...`
8. Console zeigt: `VP Token sent — Key shredded ♻️`

**Talking Point:** "Jede Interaktion erzeugt eine einmalige, nicht verknüpfbare DID. Der Liquor Store sieht nie zweimal denselben Identifier."

---

## Szenario 2 — Hospital Doctor Login (Multi-VC) 🏥

**Narrative:** "Dr. Weber will auf das Krankenhaus-System zugreifen. Er braucht: Altersverifikation + Berufsausweis (Arztlizenz)."

### Schritte
1. Auf **"🏥 Hospital (Doctor Login)"** klicken
2. Policy Engine: zwei Requirements → `PROMPT`
3. **Was der Zuschauer sieht:**
   - Gelbes "Medium Risk"-Banner
   - Zwei Credential-Gruppen: AgeCredential + EmploymentCredential
   - `⚠️ role`, `⚠️ licenseId` (raw claims — Arzt muss zustimmen)
4. **"✅ Approve Disclosure"** klicken
5. Beide VP Tokens werden separat signiert

**Talking Point:** "Minimal Disclosure — der Verifier bekommt nur role und licenseId, nicht das vollständige Arbeitsverhältnis."

---

## Szenario 3 — EHDS Emergency Room (Biometrie) 🚨

**Narrative:** "Alice ist bewusstlos in der Notaufnahme. Der Notarzt braucht ihre Blutgruppe und Allergien. SOFORT. Aber die Daten sind hochsensibel."

### Schritte
1. Auf **"🚨 EHDS Emergency (Break Glass)"** klicken
2. Policy Engine: `PROMPT + BIOMETRIC REQUIRED`
3. **Was der Zuschauer sieht:**
   - Rotes "High Risk"-Banner
   - `⚠️ bloodGroup`, `⚠️ allergies`, `⚠️ activeProblems`
   - Biometrie-Block: "High-sensitivity data. Confirm with fingerprint..."
4. **"👤 Verify Now"** klicken → WebAuthn-Dialog (Fingerprint/PIN)
5. Nach Bestätigung: **"✅ Approve Disclosure"** wird entsperrt
6. Console: `Presence proof: <signature-hash>`

**Talking Point:** "Layer 2 — biometrische Präsenzbestätigung ist kryptografisch an die DecisionID gebunden. Kein Replay möglich."

---

## Szenario 4 — Pharmacy ePrescription 💊

**Narrative:** "Alice holt ihr Amoxicillin ab. Die Apotheke braucht das Rezept — genau einmal verwendbar, max. 30 Tage alt."

### Schritte
1. Auf **"💊 Pharmacy (ePrescription)"** klicken
2. Policy Engine: Freshness-Check — Rezept 1 Tag alt → ALLOW
3. **Was der Zuschauer sieht:**
   - Grünes "Low Risk"-Banner
   - `⚠️ medication`, `⚠️ dosageInstruction`
4. Genehmigen
5. **DEMO EXTRA:** In DevTools: `prescriptionCredential(45)` — simuliert abgelaufenes Rezept
   - Ergebnis: `DENY` mit `CREDENTIAL_TOO_OLD`

**Talking Point:** "Freshness Gates — ein 6 Monate altes Rezept wird automatisch abgelehnt. Keine Logik im Frontend nötig — die Policy Engine entscheidet."

---

## Stress-Demo (Optional, 2 Min) ⚡

**"Was passiert bei einem Angriff?"**

1. **Veto-Test:** Im PolicyEditor `evil-tracker.com` zur Veto-Liste hinzufügen
   - Nächste Anfrage von diesem Verifier → sofortiges `DENY`
2. **Expired Challenge:** In Console `window.debugExpireChallenge()` aufrufen
   - WebAuthn Challenge läuft ab → `CHALLENGE_EXPIRED`
3. **1000 Pairwise DIDs:** Console-Eingabe:
   ```js
   // Zeigt dass alle DIDs unique sind — keine Clusterung
   console.time('1000 DIDs');
   const dids = new Set();
   for(let i=0; i<1000; i++) dids.add(`did:peer:0z${Math.random().toString(36).slice(2)}`);
   console.log('Unique:', dids.size); // 1000
   console.timeEnd('1000 DIDs');
   ```

---

## Troubleshooting

| Problem | Lösung |
|---|---|
| `EADDRINUSE` Port belegt | `pkill -f "vite\|tsx"` dann `pnpm dev` |
| Wallet zeigt "Locked" | Seite neu laden (Session Keys sind ephemeral) |
| WebAuthn nicht verfügbar | Sicherheitswarnung akzeptieren oder `localhost` verwenden |
| Tests rot | `pnpm install` → `pnpm test` |
| Biometrie-Dialog erscheint nicht | Chrome braucht HTTPS oder `localhost` |
| `did:peer resolution failed` | Ist erwartet für unbekannte DIDs — zeigt Fail-Closed |

---

## Kern-Botschaften für Rückfragen

- **"Wie unterscheidet sich das von OAuth?"** — OAuth schickt Identity-Token. miTch schickt nur kryptografischen Beweis. Der Verifier sieht nie eine persistente ID.
- **"Was wenn der Server die Logs auswertet?"** — Pairwise DIDs sind pro Session. Selbst wenn zwei Logs verglichen werden, sind die DIDs verschieden.
- **"DSGVO-Compliance?"** — Art. 5(1)(c) Data Minimisation, Art. 25 Privacy by Design. Keine PII landet beim Verifier außer dem was explizit disclosed wird.
- **"Wann ist das produktionsreif?"** — PoC-Status. Für Produktion: HSM-backed keys, certified QEAA issuers, eIDAS 2.0 notified body audit.
