# First-mover options and EU legal variance — 2026-11-23

Status: PROPOSED research note, not a decision and not buyer evidence. It extends the #284 brief ([`FIRST_PAYING_USE_CASE_DECISION_BRIEF_2026-11-23.md`](FIRST_PAYING_USE_CASE_DECISION_BRIEF_2026-11-23.md)).
Method: desk research by research agents on 2026-11-23. Several sources are secondary trackers or vendor pages and are marked as such. Every "UNKNOWN" stays unknown until a dated primary source is found. Legal points are not legal advice.

## 1. Question

Age verification is crowded. The EU age verification app is free, and IDV list prices are USD 0.10–1.89 per check (#326). Where could miTch (RP-side policy and evidence) or VeriCred (issuer gateway) be early instead of late?

## 2. Ranked options

| # | Niche | Hard trigger | Competition found | Window (assessment) |
|---|---|---|---|---|
| 1 | **RP-side registration-scope checks and purpose evidence**: check a request against the RP's own registration certificate before it is sent, and record why it was allowed | National registers public via a common API from 24 Dec 2026; registration certificates mandatory (IR 2026/1730); private RPs accept wallets from about 24 Dec 2027 (Art. 5f(2)) | Intermediaries and certificate vendors (Procivis registry, eID Easy Wallet Hub, itsme intermediary, Lissi connector, Namirial). **No dedicated pre-send scope check found.** Academic prior art: Sokolov, "Who Assures the Verifier?", arXiv 2609.26220 (Aug 2026) | **Open**, about 12–18 months before vendors bundle it |
| 2 | **RP-side mandate and representation checks** ("may this person act for company X, within limit Y?") | Directive (EU) 2025/25 (EU Company Certificate, digital power of attorney): transposition 31 Jul 2027, application 31 Jul 2028. European Business Wallet COM(2025) 838 in trilogue; public-sector acceptance about 2029 | Spherity (with Bundesanzeiger), Credenco, Namirial, QTSPs | **Open but slow** |
| 3 | **Issuer gateway for small DACH issuers** (chambers, training providers, small universities). This is VeriCred's own field | eIDAS Art. 45e attributes (relative date, not confirmed); Skills Portability Act COM(2026) 992 (proposal) | More than 10 vendors plus the free EU reference issuer and Europass EDC | **Narrowing**: the remaining gap is hosted service and operations |
| 4 | AI-agent delegation credentials | None (OIDF paper Oct 2025; Google AP2, Visa TAP) | Big-tech protocols | Open, but no buyer and no deadline |
| 5 | mDL car rental / wallet hotel check-in | mDL default about 2030+ (Directive (EU) 2025/2205); national guest-registration law | IDV and mdoc SDK vendors; Chekin in ES | **Closed** for a small team |

**Assessment.** Option 1 is the only one with a dated legal trigger within 13 months and a gap observed in our own test. In #326, the official verifier v0.12.0 sent a request outside its certificate without complaint. Under IR 2026/1730, that check belongs to the wallet, so the result reaches the user as a warning. Option 1 is also the most direct test of the #143 hypothesis (governance and evidence, not transport), and it works for any use case, including hotels and age. It does not depend on picking a vertical first.

Likely buyers, in order of reachability:
1. Intermediaries, which carry the risk for many RPs; an OEM or licence route.
2. Regulated RPs facing the December 2027 deadline.
3. Registrars and supervisors that need conformance evidence.

These are hypotheses for the G1 interviews (#328), not findings.

**Risks:**
- Certificate vendors or intermediaries add the feature themselves.
- The arXiv paper already proposes an evidence receipt. Build on it and cite it; do not claim it as new.
- VeriCred fits as a test issuer for conformance runs, not as the lead product.

Existing work it connects to: #183 (registered-attribute binding, wallet side), #143 (category hypothesis), #284.

## 3. EU legal variance

One RP-side product meets different national rules in six areas. The facts below come from the research agents' sources; everything marked UNKNOWN is unresolved.

| Area | EU baseline | What differs by member state | Examples | Main unknowns |
|---|---|---|---|---|
| Wallet availability | Wallet per member state by 24 Dec 2026 (Reg. 2024/1183) | Name, launch date, formats | DE "d-you" planned 2 Jan 2027; IT IT-Wallet live since Dec 2024; DK AltID live since Jun 2026; AT upgrade without a date; NL 2027 | No certified EUDI wallet found as of 23 Nov 2026 (eudigo tracker) |
| RP registration | IR 2025/848, amended by IR 2026/1730; registers via common API from 24 Dec 2026 | Registrar, process, fees, API | IT: AgID (DPCM 31 Jul 2026); FI: Traficom (Act 810/2026); DE: BVA in the DIdG vs "bundesnetzagentur" in the BMI architecture draft (**conflict**); AT, FR, NL, IE, ES: none named | GR, CY; how RPs operate where no registrar exists |
| Mandatory acceptance | Art. 5f: public sector; private RPs that require strong authentication (about 24 Dec 2027); VLOPs | Which national laws require strong authentication | No member state list of obligated sectors found | All focus countries |
| Age rules | DSA Art. 28 guidelines (Jul 2025); Recommendation C(2026) 4225 (app by end 2026) | Thresholds and accepted proof schemes | FR ARCOM double anonymity; IT AGCOM 96/25/CONS; DE KJM-approved AVS; GR under-15 social-media ban from 1 Jan 2027; ES bill (16) | KJM position on EUDI/"d-you"; EU Kids Act contents |
| Guest registration | CISA Art. 45 (foreign guests) | Scope, retention, identification mode | AT all guests, 7 years; DE foreign guests only since 2025; FR foreigners, 6 months; IT Alloggiati Web; ES SES.HOSPEDAJES (RD 933/2021) | IT remote identification after the Consiglio di Stato ruling (21 Nov 2025) |
| National identifiers and logs | GDPR Art. 87; Art. 6(1)(c) | Use of national ID numbers; retention | NL BSN only with a statutory basis (UAVG Art. 46); DE PAuswG §20(2) ID copies; AT sector-specific bPK | DK CPR, FR NIR; how bPK maps to the PID |

Consequence for the product (assessment): policies need a jurisdiction dimension (country × purpose × minimum claims × retention). No single EU-wide default is safe. This matches the existing `policy-engine/jurisdiction.ts` direction; its current coverage was not checked here.

## 4. Tracking

- Option 1 is tracked as #338 (sub-issue of #284).
- EU legal variance: parent #330, linked to #283, #284, #325, #327, #183, #182, #184, #172 and #97.

| Issue | Work item |
|---|---|
| #331 | Wallet status and RP registrar per member state |
| #332 | Art. 5f mandatory-acceptance obligations |
| #333 | Age threshold and accepted proof scheme per jurisdiction |
| #334 | Guest-registration datasets (AT, DE, FR, IT, ES) |
| #335 | National-identifier minimisation guard |
| #336 | Retention and deletion per jurisdiction and legal basis |
| #337 | Legal-source watch |

Certificate validation and registered-attribute binding on the wallet side stay in #183 and are not duplicated.

## 5. Sources (opened by research agents on 2026-11-23; secondary sources marked)

- [IR (EU) 2026/1730](https://eur-lex.europa.eu/eli/reg_impl/2026/1730/oj) (Spanish OJ text: [BOE](https://www.boe.es/doue/2026/1730/L00001-00006.pdf)); [IR (EU) 2025/848](https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj); [Reg. (EU) 2024/1183](https://eur-lex.europa.eu/eli/reg/2024/1183/oj)
- Registrar and wallet trackers (secondary): [eudigo.eu RP registration](https://eudigo.eu/en/relying-party-registration/), [eudigo wallets](https://eudigo.eu/en/eudi-wallets-in-the-eu/), [eudiwalletrp.com](https://eudiwalletrp.com/national-trackers/member-states/), [eID Easy July 2026](https://www.eideasy.com/blog/eu-digital-identity-wallets-july-2026)
- [Bundestag DIdG, 15 Oct 2026](https://www.bundestag.de/dokumente/textarchiv/2026/kw42-de-digitale-identitaeten-gesetz-1223586); [BMI architecture draft](https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/flows/Wallet-Relying-Party-Authentication)
- Vendors: [Procivis](https://www.procivis.ch/insights/wallet-relying-party-registration), [eID Easy](https://www.eideasy.com/blog/eudiw-relying-party-registration), [itsme](https://www.itsme-id.com/business/use-case/eudiw-intermediary-service), [Namirial](https://focus.namirial.com/de/relying-party-werden/)
- Business wallet and mandates: [COM(2025) 838 procedure](https://eur-lex.europa.eu/procedure/EN/2025_358), [Directive (EU) 2025/25 summary](https://oeil.europarl.europa.eu/oeil/en/document-summary?id=1800869)
- mDL: [Directive (EU) 2025/2205](https://eur-lex.europa.eu/eli/dir/2025/2205/oj); [EC mDL manual](https://ec.europa.eu/digital-building-blocks/sites/display/EUDIGITALIDENTITYWALLET/The+mobile+Driving+License+manual)
- Age: [Commission recommendation news](https://digital-strategy.ec.europa.eu/en/news/commission-urges-member-states-rollout-eu-age-verification-app); [AGCOM 96/25/CONS](https://www.agcom.it/sites/default/files/media/allegato/2026/Resolution_no_96_25_CONS_courtesy_translation.pdf)
- Guest registration: [USP Gästeverzeichnis (AT)](https://www.usp.gv.at/themen/brancheninformationen/gastronomie-und-tourismus/gaesteverzeichnis.html); [Haufe (DE, secondary)](https://www.haufe.de/recht/weitere-rechtsgebiete/wirtschaftsrecht/meldepflicht-in-beherbergungsstaetten_210_639508.html); [service-public.fr](https://www.service-public.gouv.fr/particuliers/vosdroits/R41514)
- Identifiers: [PAuswG §20](https://www.gesetze-im-internet.de/pauswg/__20.html)
- Prior art: Sokolov, "Who Assures the Verifier?", arXiv 2609.26220
