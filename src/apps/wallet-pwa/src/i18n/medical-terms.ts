/**
 * medical-terms.ts
 *
 * EHDS Compliance (T-C3): Localized medical terms for Wallet UI.
 * Maps SNOMED CT / LOINC codes to human-readable strings.
 */

export const MEDICAL_I18N: Record<string, Record<string, string>> = {
    'bloodGroup': {
        en: 'Blood Group',
        de: 'Blutgruppe',
        es: 'Grupo sanguíneo',
        nl: 'Bloedgroep'
    },
    'allergies': {
        en: 'Allergies',
        de: 'Allergien',
        es: 'Alergias',
        nl: 'Allergieën'
    },
    'activeProblems': {
        en: 'Active Problems',
        de: 'Aktive Diagnosen',
        es: 'Problemas activos',
        nl: 'Actieve problemen'
    },
    'emergencyContacts': {
        en: 'Emergency Contacts',
        de: 'Notfallkontakte',
        es: 'Contactos de emergencia',
        nl: 'Contacten voor noodgevallen'
    },
    'medication': {
        en: 'Medication',
        de: 'Medikation',
        es: 'Medicamentos',
        nl: 'Medicatie'
    },
    // Common Values
    'Penicillin': {
        en: 'Penicillin',
        de: 'Penicillin',
        es: 'Penicilina',
        nl: 'Penicilline'
    },
    'Asthma': {
        en: 'Asthma',
        de: 'Asthma',
        es: 'Asma',
        nl: 'Astma'
    }
};

/**
 * Translates a medical term or key into the requested locale.
 * Fallback to EN.
 */
export function tMedical(key: string, locale: string = 'en'): string {
    const entry = MEDICAL_I18N[key];
    if (!entry) return key;
    return entry[locale] || entry['en'] || key;
}
