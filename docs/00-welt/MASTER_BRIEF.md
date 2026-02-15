# MASTER BRIEF: miTch – The Forgetting Layer
**Single Source of Truth v1.0**

## 1. One-liner
miTch ist eine technische Convenor-Infrastruktur, die digitalen Diensten **Compliance-as-a-Service** bietet, indem sie **automatisiertes, kryptografisches Vergessen** (Crypto-Shredding) und datensparsame Verifikationen (z.B. Altersnachweis) durchsetzt, ohne selbst Daten zu speichern.

## 2. Nicht-Ziele (Non-Goals)
*   **Kein Identity Provider (IdP):** Wir geben keine Identitäten heraus (wir nutzen bestehende wie eID, Bank-ID).
*   **Kein Daten-Marktplatz:** Wir ermöglichen keinen Verkauf von Nutzerdaten.
*   **Keine "Super-App":** Wir sind Infrastruktur/SDK/Protokoll, keine Consumer-Brand-App (White-Label-fähig).
*   **Keine zentrale Datenbank:** Wir speichern **niemals** Nutzerattribute (PII) zentral.
*   **Kein "Trust me, bro":** Sicherheit basiert auf mathematischen Garantien, nicht auf Versprechen.

## 3. Kernthese: Convener & Automatisches Vergessen
*   **Convenor-Rolle:** miTch definiert und erzwingt das Regelwerk (Policy Manifest) für ein Ökosystem. Vertrauen entsteht, weil das System strukturell nichts wissen *kann*.
*   **Automatisches Vergessen:** Im Gegensatz zu Datenbanken, die "behalten" als Standard haben, ist miTch auf "Vergessen" optimiert. Daten existieren nur transaktional und werden durch **Crypto-Shredding** (Löschen des kryptografischen Schlüssels) unwiederbringlich vernichtet, sobald der Zweck erfüllt ist. Compliance ist kein manueller Prozess, sondern Architektur.

## 4. Beachhead-PoC: "Altersnachweis ohne Tracking"
*   **Problem:** EU-DSGVO-Bericht fordert strengeren Kinderschutz, aber Alterschecks führen oft zu massiver Datensammlung (Pasing-Scans, Tracking) oder sind unsicher.
*   **Lösung:** Ein "Zero-Knowledge Age Check". Der Nutzer beweist "Ich bin über 18", ohne Geburtsdatum oder Namen an den Shop zu geben. Der Shop erhält die Garantie, speichert aber keine toxischen Kundendaten.
*   **Warum jetzt?** Hoher regulatorischer Druck (EU-DSGVO Review, DSA, EUDI Wallet Roadmap). KMUs und Plattformen brauchen eine Haftungsbefreiung („Liability Shield“).

## 5. Monetarisierung (Hypothese)
*   **Wer zahlt?** Die **Diensteanbieter / Verifier** (Shops, Plattformen).
*   **Warum?**
    1.  **Risk Reduction:** Keine Speicherung von PII = kein Risiko bei Data Breaches.
    2.  **Compliance Costs:** Automatische Erfüllung von DSGVO-Löschpflichten spart manuelle Prozesse und Bußgelder.
    3.  **Conversion:** Schnellere Onboarding-Prozesse (Single-Click-Verify) ohne Formulare.

## 6. Trust- & Rollenmodell
*   **Holder (Nutzer/Wallet):** Hält die Hoheit über die eigenen Daten und Schlüssel lokal (Edge).
*   **Issuer (Vertrauensquelle):** Staat, Bank oder Telco. Bestätigt Attribute (z.B. "Geburtsdatum: 01.01.1990") digital signiert (Verifiable Credential).
*   **Verifier (Dienstleister):** Fragt Fakten ab (z.B. "Ü18?"). Erhält nur das Ergebnis (True/False) + kryptografischen Beweis, keine Rohdaten.
*   **miTch (Convener):** Stellt die Protokoll-Schienen und Policies.
    *   Regelt: "Verifier X darf nur Ü18 fragen, nicht Name".
    *   Garantiert: Datenfluss war verschlüsselt und Schlüssel wurde danach gelöscht.
    *   *Sieht: Metadaten für Audit (Wer, Wann, Was-Typ), aber NIEMALS den Inhalt.*

## 7. "Vergessen als Service" – Operationalisierung & Audit
*   **Technisch:** Daten werden für eine Transaktion mit einem ephemeren (flüchtigen) Schlüssel `K_trans` verschlüsselt. Nach Abschluss der Transaktion wird `K_trans` sicher gelöscht (überschrieben). Ohne Schlüssel sind die Daten wertloser Datenmüll (Crypto-Shredding).
*   **Audit-Beweis:**
    1.  **Log:** "Key `ID-123` erstellt um 12:00:00".
    2.  **Log:** "Key `ID-123` genutzt für Check bei `Shop-A` um 12:00:01".
    3.  **Log:** "Key `ID-123` zerstört (zeiled) um 12:00:02".
    *   Der Auditor prüft die Unversehrtheit der Logs und den Code, der die Löschung erzwingt.

## 8. Risiken & Offene Annahmen
1.  **Regulatory Acceptance:** Akzeptiert der Gesetzgeber "Crypto-Shredding" als rechtssichere Löschung? (Hypothese: Ja, da Stand der Technik).
2.  **Issuer-Abhängigkeit:** Wir brauchen Issuer (z.B. Banken), die VCs ausstellen. Für den PoC müssen wir ggf. einen eigenen Mock-Issuer bauen.
3.  **User Adoption:** Installieren Nutzer eine App/Wallet? (Lösung: Integration als SDK in bestehende Apps bevorzugt).
4.  **Device Security:** Was, wenn das Handy des Nutzers kompromittiert ist?
5.  **Complexity:** Verstehen KMUs den Vorteil von "Zero Knowledge" vs. "Ich will aber die Daten haben"?
