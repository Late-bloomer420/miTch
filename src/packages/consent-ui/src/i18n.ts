import type { ConsentStrings } from './types';

export const DEFAULT_STRINGS_EN: ConsentStrings = {
    title: 'Consent required',
    purposePrefix: 'is requesting access for:',
    sectionClaims: 'Requested data',
    sectionPredicates: 'Requested proofs',
    stateRequested: 'requested',
    stateAllowed: 'allowed',
    stateWithheld: 'withheld',
    stateDenied: 'denied',
    btnApprove: 'Share & continue',
    btnCancel: 'Cancel',
    emptyClaims: 'No raw data requested.',
    emptyPredicates: 'No proofs requested.',
    deniedByPolicy: 'denied by policy',
    failClosedHint: 'Unselected items stay withheld.',
};

export const DEFAULT_STRINGS_DE: ConsentStrings = {
    title: 'Zustimmung erforderlich',
    purposePrefix: 'fordert Zugriff an für:',
    sectionClaims: 'Angeforderte Daten',
    sectionPredicates: 'Angeforderte Nachweise',
    stateRequested: 'angefragt',
    stateAllowed: 'freigegeben',
    stateWithheld: 'zurückgehalten',
    stateDenied: 'verweigert',
    btnApprove: 'Teilen & fortfahren',
    btnCancel: 'Abbrechen',
    emptyClaims: 'Keine Rohdaten angefragt.',
    emptyPredicates: 'Keine Nachweise angefragt.',
    deniedByPolicy: 'durch Policy verweigert',
    failClosedHint: 'Nicht ausgewählte Felder bleiben zurückgehalten.',
};

export function stringsForLang(lang: string | null | undefined): ConsentStrings {
    const tag = (lang ?? '').toLowerCase().split('-')[0];
    if (tag === 'de') return DEFAULT_STRINGS_DE;
    return DEFAULT_STRINGS_EN;
}
