export type LanguageCode = 'de' | 'en' | 'es' | 'nl';

// Get language from browser or default to EN
export function getBrowserLanguage(): LanguageCode {
    const lang = (navigator.language || 'en').toLowerCase();
    if (lang.startsWith('de')) return 'de';
    if (lang.startsWith('es')) return 'es';
    if (lang.startsWith('nl')) return 'nl';
    return 'en';
}

// ── Medical Claim Translations ────────────────────────────────────────────────
// EHDS Compliance (T-C3): localized medical terms for the Wallet UI, incl. a few
// common medical *values* (e.g. Penicillin, Asthma) alongside claim *keys*.
// Consolidated from the former i18n/medical-terms.ts (SNOMED CT / LOINC-oriented)
// so there is a single source of truth for medical labels.
const CLAIM_DICTIONARY: Record<LanguageCode, Record<string, string>> = {
    en: {
        'bloodGroup': 'Blood Group',
        'dateOfBirth': 'Date of Birth',
        'givenName': 'Given Name',
        'familyName': 'Family Name',
        'allergies': 'Allergies',
        'currentMedication': 'Current Medication',
        'pastIllnesses': 'Past Illnesses',
        'vaccinationStatus': 'Vaccination Status',
        'geneticData': 'Genetic Data',
        'activeProblems': 'Active Problems',
        'emergencyContacts': 'Emergency Contacts',
        'medication': 'Medication',
        'dosageInstruction': 'Dosage Instruction',
        'refillsRemaining': 'Refills Remaining',
        // medical values (EHDS T-C3)
        'Penicillin': 'Penicillin',
        'Asthma': 'Asthma'
    },
    de: {
        'bloodGroup': 'Blutgruppe',
        'dateOfBirth': 'Geburtsdatum',
        'givenName': 'Vorname',
        'familyName': 'Nachname',
        'allergies': 'Allergien',
        'currentMedication': 'Aktuelle Medikation',
        'pastIllnesses': 'Vorerkrankungen',
        'vaccinationStatus': 'Impfstatus',
        'geneticData': 'Genetische Daten',
        'activeProblems': 'Aktive Diagnosen',
        'emergencyContacts': 'Notfallkontakte',
        'medication': 'Medikation',
        'dosageInstruction': 'Dosierungsanweisung',
        'refillsRemaining': 'Verbleibende Rezepte',
        // medical values (EHDS T-C3)
        'Penicillin': 'Penicillin',
        'Asthma': 'Asthma'
    },
    es: {
        'bloodGroup': 'Grupo Sanguíneo',
        'dateOfBirth': 'Fecha de Nacimiento',
        'givenName': 'Nombre',
        'familyName': 'Apellido',
        'allergies': 'Alergias',
        'currentMedication': 'Medicación Actual',
        'pastIllnesses': 'Enfermedades Pasadas',
        'vaccinationStatus': 'Estado de Vacunación',
        'geneticData': 'Datos Genéticos',
        'activeProblems': 'Problemas Activos',
        'emergencyContacts': 'Contactos de Emergencia',
        'medication': 'Medicamentos',
        'dosageInstruction': 'Instrucciones de Dosis',
        'refillsRemaining': 'Recargas Restantes',
        // medical values (EHDS T-C3)
        'Penicillin': 'Penicilina',
        'Asthma': 'Asma'
    },
    nl: {
        'bloodGroup': 'Bloedgroep',
        'dateOfBirth': 'Geboortedatum',
        'givenName': 'Voornaam',
        'familyName': 'Achternaam',
        'allergies': 'Allergieën',
        'currentMedication': 'Huidige Medicatie',
        'pastIllnesses': 'Eerdere Ziekten',
        'vaccinationStatus': 'Vaccinatiestatus',
        'geneticData': 'Genetische Gegevens',
        'activeProblems': 'Actieve Problemen',
        'emergencyContacts': 'Contacten voor Noodgevallen',
        'medication': 'Medicatie',
        'dosageInstruction': 'Doseringsinstructie',
        'refillsRemaining': 'Resterende Navullingen',
        // medical values (EHDS T-C3)
        'Penicillin': 'Penicilline',
        'Asthma': 'Astma'
    }
};

export function translateClaim(claimKey: string, lang: LanguageCode = getBrowserLanguage()): string {
    return CLAIM_DICTIONARY[lang]?.[claimKey] || claimKey;
}

// ── ReasonCode Translations ──────────────────────────────────────────────────
const REASON_DICTIONARY: Record<LanguageCode, Record<string, string>> = {
    en: {
        'CONSENT_REQUIRED': '✋ Explicit consent required',
        'SENSITIVE_CLAIM': '⚠️ Contains sensitive data',
        'PRESENCE_REQUIRED': '🔐 Biometric presence required',
        'HIGH_RISK_VERIFIER': '🚨 Unknown / high-risk verifier',
        'HDAB_PERMIT_REQUIRED': '🏥 Research permit (HDAB) required',
        'SECONDARY_USE_DENIED': '🚫 Secondary use blocked by policy',
        'GEO_SCOPE_VIOLATION': '🌍 Verifier outside allowed region',
        'BREAK_GLASS_ACTIVATED': '🚨 EMERGENCY: Break-Glass Activated'
    },
    de: {
        'CONSENT_REQUIRED': '✋ Explizite Zustimmung erforderlich',
        'SENSITIVE_CLAIM': '⚠️ Enthält sensible Daten',
        'PRESENCE_REQUIRED': '🔐 Biometrische Anwesenheit erforderlich',
        'HIGH_RISK_VERIFIER': '🚨 Unbekannter / risikobehafteter Verifier',
        'HDAB_PERMIT_REQUIRED': '🏥 Forschungsgenehmigung (HDAB) erforderlich',
        'SECONDARY_USE_DENIED': '🚫 Sekundärnutzung durch Policy untersagt',
        'GEO_SCOPE_VIOLATION': '🌍 Verifier außerhalb der erlaubten Region',
        'BREAK_GLASS_ACTIVATED': '🚨 NOTFALL: Break-Glass aktiviert'
    },
    es: {
        'CONSENT_REQUIRED': '✋ Se requiere consentimiento explícito',
        'SENSITIVE_CLAIM': '⚠️ Contiene datos sensibles',
        'PRESENCE_REQUIRED': '🔐 Presencia biométrica requerida',
        'HIGH_RISK_VERIFIER': '🚨 Verificador desconocido / alto riesgo',
        'HDAB_PERMIT_REQUIRED': '🏥 Permiso de investigación (HDAB) requerido',
        'SECONDARY_USE_DENIED': '🚫 Uso secundario bloqueado por política',
        'GEO_SCOPE_VIOLATION': '🌍 Verificador fuera de la región permitida',
        'BREAK_GLASS_ACTIVATED': '🚨 EMERGENCIA: Break-Glass activado'
    },
    nl: {
        'CONSENT_REQUIRED': '✋ Expliciete toestemming vereist',
        'SENSITIVE_CLAIM': '⚠️ Bevat gevoelige gegevens',
        'PRESENCE_REQUIRED': '🔐 Biometrische aanwezigheid vereist',
        'HIGH_RISK_VERIFIER': '🚨 Onbekende / hoog-risico verificateur',
        'HDAB_PERMIT_REQUIRED': '🏥 Onderzoeksvergunning (HDAB) vereist',
        'SECONDARY_USE_DENIED': '🚫 Secundair gebruik geblokkeerd door beleid',
        'GEO_SCOPE_VIOLATION': '🌍 Verificateur buiten toegestane regio',
        'BREAK_GLASS_ACTIVATED': '🚨 NOODGEVAL: Break-Glass geactiveerd'
    }
};

export function translateReason(reasonCode: string, lang: LanguageCode = getBrowserLanguage()): string {
    return REASON_DICTIONARY[lang]?.[reasonCode] || REASON_DICTIONARY['en']?.[reasonCode] || reasonCode;
}
