# miTch Legal — DSGVO-Basis & Crypto-Shredding

**Quelle: docs/04-legal/MEMO_GDPR_SHREDDING.md (Dr. Jur. Stefan Weber, Wien, 2026-01-26)**

---

## Kernaussage (Legal Opinion)

Crypto-Shredding von `K_trans` (AES-256) nach Session-Abschluss erfüllt das  
"Recht auf Löschung" nach **DSGVO Art. 17**.

Basis:
- GDPR Recital 26: Anonymisierte Daten sind keine personenbezogenen Daten mehr
- EDPB Guidelines 04/2020: Split-Key-Encryption + Schlüsselvernichtung anonymisiert effektiv
- Österreichische DSB: Hat Löschkonzepte anerkannt, bei denen Re-Identifikation technisch unmöglich ist
- DSGVO Art. 32(1)(a): Verschlüsselung als explizit genannte geeignete Maßnahme

---

## Wie Crypto-Shredding funktioniert

```
1. Session startet → K_trans (AES-256) wird generiert (einmalig, pro Session)
2. Alle PII der Session → mit K_trans verschlüsselt → in Audit-Log geschrieben
3. Session endet → K_trans wird überschrieben (SecureBuffer.shred()) + Pointer nullified
4. Rückstand im Log: Ciphertext = mathematisch nicht unterscheidbar von Rauschen
```

Ohne `K_trans`: keine Wiederherstellung möglich. Brute-Force AES-256: computationally infeasible.

---

## Verbleibende Risiken (aus Legal Opinion)

| Risiko | Mitigation |
|---|---|
| **Quantum-Angriff** (BSI: praktisch ab ~2030) | Post-Quantum Migration (ML-DSA) auf Roadmap; Datenretention < kryptographischer Horizont |
| **Key Leakage vor Shredding** | Memory Protection (perspektivisch TEE), Code-Audits |

---

## Was das für die Architektur bedeutet

- `K_trans` darf **niemals** geloggt werden
- `K_trans` muss im Memory sicher überschrieben werden (kein GC-Dependency)
- Der Audit-Log darf nur Ciphertext enthalten, nie Plaintext-PII
- Die Legal Opinion deckt **diese Implementierung** ab — Änderungen am Shredding-Mechanismus erfordern Neubewertung

---

## Status

Legal Opinion: VORHANDEN (intern)  
Unabhängiges externes Audit: AUSSTEHEND (empfohlen vor erster kommerzieller Nutzung)
