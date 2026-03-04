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
        'geneticData': 'Genetic Data'
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
        'geneticData': 'Genetische Daten'
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
        'geneticData': 'Datos Genéticos'
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
        'geneticData': 'Genetische Gegevens'
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
        'HIGH_RISK_VERIFIER': '🚨 Unknown / high-risk verifier'
    },
    de: {
        'CONSENT_REQUIRED': '✋ Explizite Zustimmung erforderlich',
        'SENSITIVE_CLAIM': '⚠️ Enthält sensible Daten',
        'PRESENCE_REQUIRED': '🔐 Biometrische Anwesenheit erforderlich',
        'HIGH_RISK_VERIFIER': '🚨 Unbekannter / risikobehafteter Verifier'
    },
    es: {
        'CONSENT_REQUIRED': '✋ Se requiere consentimiento explícito',
        'SENSITIVE_CLAIM': '⚠️ Contiene datos sensibles',
        'PRESENCE_REQUIRED': '🔐 Presencia biométrica requerida',
        'HIGH_RISK_VERIFIER': '🚨 Verificador desconocido / alto riesgo'
    },
    nl: {
        'CONSENT_REQUIRED': '✋ Expliciete toestemming vereist',
        'SENSITIVE_CLAIM': '⚠️ Bevat gevoelige gegevens',
        'PRESENCE_REQUIRED': '🔐 Biometrische aanwezigheid vereist',
        'HIGH_RISK_VERIFIER': '🚨 Onbekende / hoog-risico verificateur'
    }
};

export function translateReason(reasonCode: string, lang: LanguageCode = getBrowserLanguage()): string {
    return REASON_DICTIONARY[lang]?.[reasonCode] || REASON_DICTIONARY['en']?.[reasonCode] || reasonCode;
}
