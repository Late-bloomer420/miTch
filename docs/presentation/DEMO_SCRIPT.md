# miTch Live-Demo Script (5-10 Min)

Willkommen zur Live-Demonstration von **miTch — The Forgetting Layer**. Wir zeigen heute, wie miTch als Privacy-Middleware funktioniert und wie wir das Prinzip *Verifiable Trust ohne zentralisierte Datenhaltung* in der Praxis umsetzen.

---

## Szenario 1: Liquor Store (Auto-Allow, Alter ≥18)
*Fokus: Reibungslose User Experience & Datenminimierung im Alltag (Layer 1 - Grundversorgung).*

**Was der User sieht:**
- Der Nutzer scannt einen QR-Code an der Kasse oder im Online-Shop.
- Auf dem Smartphone erscheint für den Bruchteil einer Sekunde ein "Check"-Symbol.
- Die Kasse gibt den Einkauf sofort frei. Keine Passworteingabe, kein Warten.

**Was im Hintergrund passiert:**
- Der Verifier (Liquor Store) fordert über die miTch Protection Layer API den Beweis: `Alter >= 18`.
- Die **Policy Engine** auf dem Smartphone des Nutzers prüft die Anfrage. Da es sich um eine Low-Risk-Transaktion ohne Weitergabe von Rohdaten handelt, greift die "Auto-Allow"-Policy.
- Der **Proof Builder** generiert einen Zero-Knowledge Proof (ZKP) oder abgeleiteten Claim (nur `true/false`).
- Ephemere (kurzlebige) Schlüssel werden generiert, verwendet und sofort zerstört (Crypto-Shredding).

**Privacy-Aspekt:**
- Der Verifier erfährt weder das Geburtsdatum noch den Namen. Er erhält nur ein kryptografisch sicheres "Ja, über 18".
- Die Transaktion ist unverlinkbar. Ein Tracking des Kaufverhaltens über verschiedene Geschäfte hinweg ist ausgeschlossen.

---

## Szenario 2: Hospital (User-Prompt, selektive Freigabe)
*Fokus: Souveränität des Nutzers und granulare Zustimmung (Layer 2 - Health).*

**Was der User sieht:**
- An der Patientenaufnahme scannt der Nutzer den Terminal-Code.
- Auf dem Smartphone erscheint ein **Consent Modal**: "Das Stadtkrankenhaus fordert Ihren Namen, Ihre Versichertennummer und Ihren Blutgruppen-Nachweis an."
- Der Nutzer sieht genau, welche Daten fließen, und bestätigt die Freigabe per Knopfdruck ("Allow").

**Was im Hintergrund passiert:**
- Der Verifier fragt nach GDPR Art. 9 (Gesundheitsdaten) regulierten Attributen. Dies löst in der Policy Engine zwingend einen **User-Prompt** (kein Auto-Allow möglich) aus.
- Selektive Disclosure: Der Wallet trennt die angeforderten Attribute von den restlichen Identitätsdaten (z. B. Adresse, Beruf) und verpackt nur die freigegebenen Daten in einen Payload.
- Die Daten werden mittels JWE (JSON Web Encryption) und Ephemeral Keys (`ECDH-P256`) verschlüsselt an das Krankenhaus übertragen.

**Privacy-Aspekt:**
- **Fail-Closed Prinzip:** Wenn ein erforderliches Attribut fehlt oder die Policy unklar ist, wird der Vorgang standardmäßig blockiert (Deny).
- Der Nutzer hat volle Transparenz und Kontrolle darüber, was der Verifier erhält.

---

## Szenario 3: EHDS Emergency (Biometric + Break-Glass)
*Fokus: High-Assurance, starke Authentifizierung und Notfallzugriff (EHDS Compliance).*

**Was der User sieht:**
- **Standardfall:** Ein Arzt greift auf die historische Patientenakte (EHDS) zu. Der Nutzer erhält eine Push-Anfrage und muss diese via FaceID / TouchID (WebAuthn) bestätigen.
- **Break-Glass (Notfall):** Der Patient ist bewusstlos. Der Arzt nutzt ein Notfallprotokoll am Terminal. Der Zugriff wird gewährt, aber intensiv geloggt. Der Patient wird im Nachhinein benachrichtigt.

**Was im Hintergrund passiert:**
- Das System fordert ein Step-Up auf **WebAuthn Biometric Verification**. Die letzte biometrische Verifikation wird gegen den `requireConsentTimeoutMinutes` Timer geprüft.
- Beim Break-Glass-Szenario wird eine spezielle Policy getriggert: Der lokale **Audit Log** (Immutable Hash-Chain) zeichnet den Notfallzugriff manipulationssicher auf.
- Die Signaturschlüssel arbeiten strikt getrennt von den Verschlüsselungsschlüsseln (Key Separation: `ECDSA` vs. `ECDH-P256`).

**Privacy-Aspekt:**
- Höchste Schutzstufe für sensible Gesundheitsdaten. Selbst bei gestohlenem Gerät verhindert der WebAuthn-Layer einen Missbrauch.
- Transparenz nach dem Vorfall ("Auditability") ist systemisch erzwungen.

---

## Szenario 4: Pharmacy (ePrescription + Nullifier)
*Fokus: Double-Spending-Schutz ohne Identitäts-Leak.*

**Was der User sieht:**
- Der Nutzer löst ein E-Rezept in der Apotheke ein.
- Das Apothekensystem bestätigt die Einlösung und fügt das Rezept hinzu.
- Das Rezept wird im Wallet als "eingelöst" markiert.

**Was im Hintergrund passiert:**
- Der **Proof Builder** erstellt einen kryptografischen Nullifier (eine eindeutige, deterministische Hash-Zeichenfolge für dieses spezielle Rezept).
- Der miTch Verifier prüft im Hintergrund den **Revocation Status** (z.B. per StatusList2021).
- Der Nullifier wird bei der Apotheke registriert. Versucht der Nutzer, das gleiche Rezept woanders einzulösen, wird der Nullifier als "bereits verwendet" erkannt, ohne die Identität preiszugeben.

**Privacy-Aspekt:**
- Verhinderung von Mehrfacheinlösungen (Double-Spending), absolut anonym.
- Die Apotheke weiß, dass das Rezept gültig und ungenutzt ist, muss aber nicht zwingend erfahren, wer der Patient ist. 

---
*Ende der Demo.*
