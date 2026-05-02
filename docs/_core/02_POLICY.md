# miTch Policy — Nicht-Verhandelbarkeiten

**Version: 1.0 | Scope: DACH / EU**

---

## 5 Invarianten (dürfen nie gebrochen werden)

1. **Rule over Authority** — Regeln entscheiden, keine Autorität
2. **Data Minimization by Construction** — Minimalität ist Architektur, nicht Einstellung
3. **User Sovereignty** — Nutzer ist Root of Trust, nicht Plattform
4. **Non-Linkability** — Verschiedene Presentationen dürfen nicht korrelierbar sein
5. **Fail-Closed** — Ambiguität = DENY, nie ALLOW

---

## 4 Absolute Verbote (Never Events)

- Zentrale Nutzerprofile
- Cross-Service-Tracking
- Datenverkauf
- Kommerzialisierung von Grundrechten (Teilhabe ohne Datenzwang)

---

## Rolle von miTch

- miTch ist **kein** Issuer (stellt keine Credentials aus)
- miTch ist **kein** Verifier (prüft keine Identitäten im Auftrag von Dritten)
- miTch ist **Convener** — setzt Regeln und erzwingt sie technisch

Vertrauen entsteht nicht dadurch, dass miTch etwas *weiß*,  
sondern dadurch, dass überprüfbar festgelegt ist, **was niemand wissen darf**.

---

## Honesty Check (Architektur)

- Kein TEE/Hardware-Attestation behaupten, solange nicht implementiert und prüfbar
- Security-Posture muss explizit trennen: Software-Only vs. Hardware-backed
- Keine Behauptungen über ZK-Stärke ohne konkrete Implementierung

---

*Quelle: docs/00-welt/mitch_policy_manifest.md + docs/00-welt/03_Architecture_Core.md*
