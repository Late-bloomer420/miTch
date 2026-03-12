/**
 * PoC scenario claims — hardcoded credential data per demo scenario.
 * In production, these would come from stored credentials in SecureStorage.
 */
export const SCENARIO_CLAIMS: Record<string, Record<string, unknown>> = {
    'liquor-store': {
        age: 24,
        birthDate: '2000-01-01',
        name: 'Max Mustermann',
        address: 'Zirl, AT',
        nationalId: 'AT-123456',
    },
    'doctor-login': {
        age: 35,
        role: 'Surgeon',
        licenseId: 'MED-998877',
        employer: 'St. Mary Hospital',
        salary: 'redacted',
        homeAddress: 'redacted',
    },
    'ehds-er': {
        bloodGroup: 'A+',
        allergies: 'Penicillin, Cashew nuts',
        emergencyContacts: 'Mother: +49-151-555-0100',
        activeProblems: 'Asthma',
        diagnosis: '[full history]',
        geneticData: '[genetic profile]',
        insuranceId: 'INS-redacted',
    },
    'pharmacy': {
        medication: 'Amoxicillin 500mg',
        dosageInstruction: '1 tablet every 8 hours',
        refillsRemaining: 2,
        diagnosis: '[prescribing diagnosis]',
        insuranceId: 'INS-redacted',
        geneticData: '[genetic markers]',
    },
    'revoked': { age: 24 },
};
