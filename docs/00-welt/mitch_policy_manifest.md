# miTch Policy Manifest

**Version:** 2.0  
**Stand:** 2026-03-06  
**Scope:** DACH / EU-first  
**Role:** Convener eines regelbasierten Identitätsökosystems  
**Leitsatz:** *"Alle sind miTch."*

---

## Präambel

miTch ist kein Identitätsanbieter, kein Datenverwalter und kein Verifikationsdienst.

**miTch ist Convener.**

Vertrauen entsteht in miTch nicht dadurch, dass eine zentrale Instanz etwas *weiß*, sondern dadurch, dass überprüfbar festgelegt ist, **was niemand wissen darf – und dass das System trotzdem funktioniert**.

Dieses Manifest beschreibt die verbindlichen Policies, nach denen miTch konzipiert, betrieben und weiterentwickelt wird.

---

## 1. Grundprinzipien (Non‑Negotiable)

1. **Rule over Authority** — Regeln gelten, nicht Meinungen. Keine Ausnahmen.
2. **Data Minimization by Construction** — Nicht weniger Daten *sammeln*, sondern technisch *unfähig* sein, mehr zu sehen.
3. **User Sovereignty** — Der Nutzer entscheidet. Immer. Ohne Standardfreigabe.
4. **Non‑Linkability** — Kein Verifier, kein Tracker, kein Cookie kann herausfinden, WER verifiziert. Alle sind miTch.
5. **EU‑First Trust** — DSGVO, eIDAS 2.0, EHDS sind nicht Compliance-Pflicht, sondern Designgrundlage.

---

## 2. Core Identity & Data Policies

- **Keine Rohdaten als Standard** — Selective Disclosure: nur das Minimum, das der Verifier braucht
- **Zweckbindung vor Verarbeitung** — Kein Zugriff ohne Policy-Match
- **Löschbarkeit durch Crypto‑Shredding** — Schlüssel vernichten = Daten vergessen
- **Transparenz über lokale Audit‑Trails** — Jede Interaktion wird lokal geloggt, nie zentral
- **Pairwise-Ephemeral Identitäten** — Pro Verifier, pro Session eine frische DID. Danach geschreddert.
- **Randomisierte Proofs** — Gleicher Credential, aber jeder Beweis sieht anders aus. Kein Fingerprint.

---

## 3. Rollenverständnis

- miTch ist weder Issuer noch Verifier
- miTch setzt Regeln und erzwingt sie technisch
- Vertrauen entsteht aus Regelkonformität, nicht aus Autorität
- **miTch schützt den Nutzer auch vor sich selbst** — kein "Alles freigeben"-Button

---

## 4. Absolute Verbote (Never Events)

- Zentrale Profile
- Cross‑Service‑Tracking
- Datenverkauf
- Kommerzialisierung von Grundrechten (Teilhabe ohne Datenzwang)
- **Persistente Identifier** — kein DID, kein Key, kein Token darf über Interaktionen hinweg korrelierbar sein
- **Stille Datenabflüsse** — jeder Zugriff auf Wallet-Daten wird dem Nutzer sichtbar gemacht

---

## 5. Unlinkability ("Alle sind miTch")

> Selbst wenn alle Verifier der Welt kooperieren — sie können keinen einzelnen Nutzer wiedererkennen.

### Technische Garantien:
- **Pairwise-Ephemeral DIDs** — Jeder Verifier sieht eine andere Identität
- **Session Keys via HKDF** — Kein Schlüssel wird zweimal verwendet
- **Proof-Randomisierung** — Kryptografische Beweise sind nicht als Fingerprint nutzbar
- **Wallet-Uniformität** — Alle miTch-Wallets sehen von außen identisch aus
- **Identitäts-Firewall** — Tracker-Zugriffe werden abgefangen, geloggt und dem Nutzer gezeigt

### Was das bedeutet:
Ein Nutzer verifiziert sein Alter bei einer Apotheke. Einen Tag später bei einem Krankenhaus. Selbst wenn Apotheke und Krankenhaus ihre Daten austauschen — sie können nicht feststellen, dass es derselbe Mensch war. Weil **alle miTch sind**.

---

## 6. EHDS-Konformität

miTch implementiert die Anforderungen der European Health Data Space Regulation (2025):
- **Primary Use**: Nutzer kontrollieren ihre Gesundheitsdaten grenzüberschreitend
- **Secondary Use Denial**: Forschungszugriff nur mit expliziter Policy + HDAB-Permit
- **Break-Glass**: Notfallzugriff mit biometrischer Bestätigung + vollständigem Audit-Trail
- **Geo-Scoping**: Datenfreigabe einschränkbar auf EU/EEA/Angemessenheitsbeschluss-Länder

---

> **miTch funktioniert nicht, weil es alles weiß – sondern weil es strukturell nichts wissen kann.**  
> **Und niemand weiß, wer miTch benutzt – weil alle miTch sind.**

*Ende des Policy Manifests v2.0*
