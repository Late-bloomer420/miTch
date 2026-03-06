# miTch Architektur: The Forgetting Layer
*Ein-Seiten-Übersicht für Fach- und Führungskräfte*

## Was ist "The Forgetting Layer"?
**miTch** fungiert als schützende Datenschicht (Middleware) zwischen der digitalen Identität eines Nutzers und den Parteien, die diese Identität überprüfen wollen (Verifiers, z.B. Krankenhäuser, Shops, Behörden). 

Anstatt rohe Identitätsdaten (PII - Personally Identifiable Information) wie in einem klassischen Ausweis zu speichern und zu übertragen, erzeugt miTch passgenaue, mathematische Beweise. Nach jeder Transaktion greift das Prinzip des **Crypto-Shreddungs**: Für die Übertragung generierte, kurzlebige Schlüssel werden sofort und unwiderruflich zerstört. Das System vergisst strukturell, nicht nur aufgrund organisatorischer "Policy-Versprechen".

## Wie funktioniert selektive Disclosure?
Selektive Disclosure (gezielte Offenlegung) bedeutet, dass immer nur exakt das preisgegeben wird, was zwingend notwendig ist. 
- **Beispiel Klassisch:** Sie zeigen im Supermarkt Ihren Ausweis. Die Kassiererin sieht Name, Adresse, Geburtsdatum und Ausweisnummer.
- **Beispiel miTch:** Das System übermittelt lediglich ein maschinenlesbares, fälschungssicheres "Ja" auf die Frage: "Ist diese Person über 18?". Alle anderen Daten verlassen das Smartphone niemals.

## Warum ist das besser als klassische ID-Checks?
1. **Keine Daten-Honeypots:** Da Unternehmen (Verifiers) keine rohen Personendaten mehr speichern, gibt es bei einem Hackerangriff auf das Unternehmen auch keine Ausweisdaten zu stehlen.
2. **Fail-Closed Prinzip:** Herrscht bei einer Anfrage Unklarheit (z.B. widersprüchliche Policies oder fehlende Erlaubnis), wird die Freigabe stets verweigert (Deny-Biased). Es gibt kein heimliches Durchwinken.
3. **Data Minimization by Construction:** Datenschutz wird durch die Architektur der Software erzwungen, nicht nur durch AGBs oder menschliches Vertrauen.
4. **Absolute Nutzersouveränität:** Die Identitätsdaten liegen sicher auf dem Endgerät (Edge-First). Es gibt keinen zentralen Server, der Bewegungsprofile erstellen kann.

---

## Architektur-Diagramm

```mermaid
flowchart LR
    subgraph Issuer["Issuer / Staat"]
        A1[Aussteller eID/Pass]
        A2[Revocation Registry]
    end

    subgraph User["User Device (Smartphone)"]
        B1[miTch Wallet]
        B2[Policy Engine\n(Regelwerk)]
        B3[Proof Builder\n(ZKP Generierung)]
        B1 <--> B2
        B2 <--> B3
    end

    subgraph RP["Requester (z.B. Krankenhaus / Shop)"]
        C1[Verification API\n(miTch Layer)]
        C2[WORM Logging\n(Nur Proofs)]
    end

    A1 -- "Stellt Credentials aus\n(einmalig)" --> B1
    C1 -- "Fordert Beweis\n(z.B. Alter > 18)" --> B2
    B3 -- "Kryptografischer Proof\n(Keine PII, Ephemeral Key)" --> C1
    C1 -- "Prüft Status" --> A2
    
    style User fill:#e6f3ff,stroke:#0066cc,stroke-width:2px
    style Issuer fill:#f9f9f9,stroke:#666,stroke-width:1px
    style RP fill:#fff2e6,stroke:#e67300,stroke-width:2px
```

*Das Diagramm zeigt: Die rohen Identitätsdaten (Issuer) verbleiben sicher auf dem User Device. Der Requester kommuniziert ausschließlich auf Basis kryptografischer Beweise (Proofs), ohne jemals den vollständigen Datensatz zu Gesicht zu bekommen.*

---

## Protokoll-Stack (EUDI/eIDAS 2.0 konform)

```
┌─────────────────────────────────────────────────┐
│              Application Layer                   │
│   Wallet PWA · Verifier Demo · Issuer Mock       │
├─────────────────────────────────────────────────┤
│              Protocol Layer                      │
│   OID4VP · OID4VCI · SIOPv2 · HAIP              │
├─────────────────────────────────────────────────┤
│              Security Layer                      │
│   DPoP (RFC 9449) · Client Attestation           │
│   WebAuthn · Key Binding JWT                     │
├─────────────────────────────────────────────────┤
│              Credential Layer                    │
│   SD-JWT VC (draft-11) · StatusList2021          │
│   Selective Disclosure · Crypto-Shredding        │
├─────────────────────────────────────────────────┤
│              Crypto Layer                        │
│   ECDSA P-256 · brainpoolP256r1 (BSI)           │
│   ECDH + HMAC-SHA-256 · HKDF · AES-256-GCM      │
├─────────────────────────────────────────────────┤
│              Privacy Layer                       │
│   Pairwise Ephemeral DIDs (did:peer:0z)          │
│   Response Padding · Timing Jitter               │
│   Anti-Oracle (3-audience deny reasons)          │
└─────────────────────────────────────────────────┘
```

### CIR Compliance (Stand Session 8)

| Regulation | Coverage | Key Requirements |
|------------|----------|-----------------|
| CIR 2024/2977 (PID + EAA) | 87% ✅ | SD-JWT VC, Key Binding, OID4VCI |
| CIR 2024/2979 (Integrity) | 80% ✅ | DPoP, Brainpool, Client Attestation, JWE |
| CIR 2024/2982 (Protocols) | 80% ✅ | OID4VP, SIOPv2, HAIP, direct_post.jwt |

Verbleibende Lücken: Status-Endpoint Deployment, brainpoolP384r1 BSI-Verifizierung, Batch Credential Issuance.
