# Konzept: Controlled Insight — "Mein Wert, meine Regeln"

**Status:** KONZEPT / DEMO-IDEE (keine Code-Implementierung)  
**Stand:** 2026-03-06  
**Autor:** Jonas  
**Bezug:** Policy Manifest v2.0, Section 3 (User Sovereignty)

---

## Beobachtung

Maschinen können Muster in menschlichem Verhalten erkennen, die selbst Experten übersehen.
Ein KI-System kann aus Gesundheitsdaten, Verhaltensmustern oder Credential-Nutzung Einsichten
ableiten, die für den Nutzer **extrem wertvoll** sein können:

- Früherkennung psychischer Belastung
- Medikamenten-Wechselwirkungen erkennen
- Verhaltensmuster sichtbar machen ("Du gehst seit 3 Wochen nicht mehr zum Sport")
- Personalisierte Gesundheitsempfehlungen

**Das Problem:** Privacy by Design schützt den Nutzer vor Missbrauch — aber nimmt ihm
gleichzeitig die Möglichkeit, von dieser Analyse zu profitieren.

---

## Prinzip: Controlled Insight

> Der Nutzer entscheidet, ob und wie viel "Verständnis" er zulässt.  
> Kein System darf ohne explizite Freigabe Einsichten ableiten.  
> Aber der Nutzer DARF sich dafür entscheiden — bewusst, informiert, jederzeit widerrufbar.

### Die drei Stufen

```
┌─────────────────────────────────────────────────────┐
│  Stufe 0: OPAQUE (Standard)                         │
│  "Niemand versteht mich — auch keine Maschine"      │
│  → Volle Unlinkability, Zero Insight, Zero Profiling │
│  → Das ist der Default. Immer.                       │
├─────────────────────────────────────────────────────┤
│  Stufe 1: MIRROR (Selbst-Einsicht)                  │
│  "ICH darf mich verstehen — sonst niemand"          │
│  → Lokale Analyse auf dem eigenen Gerät              │
│  → Muster werden NUR dem Nutzer gezeigt              │
│  → Keine Daten verlassen die Wallet                  │
│  → Beispiel: "Du hast diesen Monat 4x Gesundheits-  │
│    daten geteilt — 2x mehr als üblich"               │
├─────────────────────────────────────────────────────┤
│  Stufe 2: DELEGATE (Kontrollierte Freigabe)         │
│  "Ich erlaube DIESEM Dienst, mich zu verstehen"     │
│  → Zeitlich begrenzt, zweckgebunden, widerrufbar     │
│  → Nutzer wählt: welche Daten, welcher Dienst,       │
│    wie lange, zu welchem Zweck                       │
│  → Beispiel: "Mein Arzt darf mein Medikamenten-     │
│    muster für 6 Monate analysieren"                  │
│  → Audit-Trail zeigt genau was analysiert wurde      │
└─────────────────────────────────────────────────────┘
```

---

## Kernregeln

1. **Default ist OPAQUE** — Kein Opt-out, sondern Opt-in für Insight
2. **Insight ist lokal zuerst** — Stufe 1 passiert auf dem Gerät, nie in der Cloud
3. **Delegation ist granular** — Nicht "alles oder nichts", sondern Datenpunkt für Datenpunkt
4. **Jede Delegation ist zeitlich begrenzt** — Kein "für immer" möglich
5. **Widerruf = Crypto-Shredding** — Delegation zurückziehen = Schlüssel vernichten = Daten vergessen
6. **Audit-Trail ist Pflicht** — Nutzer sieht jederzeit: wer hat was wann analysiert

---

## Wert-Visualisierung (Demo-Idee)

### "Mein Datenwert"
Der Nutzer sieht eine Übersicht dessen, was seine Daten "wert" sind:

```
┌──────────────────────────────────┐
│  📊 Mein Datenprofil             │
│                                  │
│  Gesundheit:    ████████░░  80%  │
│  Identität:     ██████░░░░  60%  │
│  Verhalten:     ████░░░░░░  40%  │
│  Finanzen:      ██░░░░░░░░  20%  │
│                                  │
│  Geschätzter Insight-Wert:       │
│  → Für Werbung: ~€47/Jahr       │
│  → Für Forschung: ~€120/Jahr    │
│  → Für DICH: unbezahlbar        │
│                                  │
│  [Stufe 0: Opaque ✅]           │
│  [Stufe 1: Mirror aktivieren]   │
│  [Stufe 2: Delegation verwalten]│
└──────────────────────────────────┘
```

### Berechtigungs-Dashboard
```
┌──────────────────────────────────────────────┐
│  🔐 Aktive Delegationen                      │
│                                              │
│  Dr. Schmidt (Hausarzt)                      │
│  ├── Medikamentenmuster: ✅ bis 2026-09-06   │
│  ├── Vitaldaten-Trend: ✅ bis 2026-09-06     │
│  └── [Widerrufen] [Verlängern]               │
│                                              │
│  Forschungsprojekt XY (Charité)              │
│  ├── Anonymisierte Altersdaten: ✅ bis 2026-06│
│  └── [Widerrufen]                            │
│                                              │
│  ⚠️ Abgelaufen:                              │
│  Apotheke Süd — Wechselwirkung (abgelaufen)  │
│  └── Daten geschreddert am 2026-02-01 ✅     │
└──────────────────────────────────────────────┘
```

---

## Verbindung zum Manifest

- **Manifest Prinzip 3 (User Sovereignty)**: Der Nutzer entscheidet — auch PRO Analyse
- **Manifest Prinzip 4 (Non-Linkability)**: Bleibt erhalten! Delegation ≠ Tracking.
  Delegation ist explizit, zeitlich begrenzt, zweckgebunden. Tracking ist heimlich und dauerhaft.
- **Manifest Section 4 (Never Events)**: Kommerzialisierung von Grundrechten bleibt verboten.
  Aber: der Nutzer darf seinen EIGENEN Datenwert für sich nutzen.

---

## Abgrenzung

| | Tracking (verboten) | Controlled Insight (erlaubt) |
|---|---|---|
| Wer entscheidet? | Der Dienst | Der Nutzer |
| Transparenz? | Heimlich | Vollständig sichtbar |
| Zeitlich begrenzt? | Nein | Ja, immer |
| Widerrufbar? | Nein/schwer | Sofort + Crypto-Shredding |
| Zweckbindung? | Keine | Explizit definiert |
| Wert für wen? | Den Dienst | Den Nutzer |

---

> *"Privatsphäre bedeutet nicht, blind zu sein. Es bedeutet, selbst zu entscheiden, wer sehen darf."*

*Konzeptnotiz — keine Code-Implementierung geplant. Für Demo + Präsentation vorgesehen.*
