import { PolicyDenialCode, DenialAction, PolicyDenialResolution } from '@mitch/shared-types';
import { ReasonCode } from './engine';

/**
 * T-28: Policy Denial & Recovery Catalog
 * 
 * Maps internal engine ReasonCodes to user-facing messages and recovery actions.
 */
export class DenialResolver {

    /**
     * Resolve a raw ReasonCode into a structured User Experience object.
     */
    static resolve(reason: string, context: Record<string, any> = {}): PolicyDenialResolution {
        // Default Fallback
        const code = this.mapReasonToDenialCode(reason);
        const resolution = this.CATALOG[code] || this.CATALOG['NO_MATCHING_RULE'];

        // Dynamic Injection (e.g. Verifier Name)
        return {
            ...resolution,
            message: this.interpolate(resolution.message, context),
            actions: resolution.actions.map(action => ({
                ...action,
                target: this.interpolate(action.target || '', context)
            }))
        };
    }

    private static interpolate(template: string, context: Record<string, any>): string {
        return template.replace(/{(\w+)}/g, (_, key) => context[key] || '?');
    }

    private static mapReasonToDenialCode(reason: string): PolicyDenialCode {
        switch (reason) {
            case ReasonCode.UNKNOWN_VERIFIER: return 'UNKNOWN_VERIFIER';
            case ReasonCode.NO_SUITABLE_CREDENTIAL: return 'NO_SUITABLE_CREDENTIAL';
            case ReasonCode.CLAIM_NOT_ALLOWED: return 'ATTRIBUTE_BLOCKED';
            case ReasonCode.CREDENTIAL_EXPIRED:
            case ReasonCode.CREDENTIAL_TOO_OLD: return 'FRESHNESS_EXPIRED';
            case ReasonCode.NO_MATCHING_RULE: return 'NO_MATCHING_RULE';
            case ReasonCode.CONSENT_REQUIRED: return 'CONSENT_REQUIRED';
            case ReasonCode.UNTRUSTED_ISSUER: return 'UNTRUSTED_ISSUER';
            default: return 'NO_MATCHING_RULE';
        }
    }

    private static CATALOG: Record<PolicyDenialCode, PolicyDenialResolution> = {
        'UNKNOWN_VERIFIER': {
            reasonCode: 'UNKNOWN_VERIFIER',
            title: 'Unbekannter Service',
            message: 'Dieser Service ({verifierId}) ist nicht im Register. Fortfahren auf eigenes Risiko.',
            severity: 'CRITICAL',
            learnMoreUrl: 'https://mitch.example/policies#UNKNOWN_VERIFIER',
            actions: [
                { id: 'act_override', label: 'Trotzdem fortfahren', type: 'OVERRIDE_WITH_CONSENT', requiresConfirm: true },
                { id: 'act_check', label: 'Verifier prüfen', type: 'LEARN_MORE', requiresConfirm: false }
            ]
        },
        'NO_SUITABLE_CREDENTIAL': {
            reasonCode: 'NO_SUITABLE_CREDENTIAL',
            title: 'Nachweis fehlt',
            message: 'Du hast kein passendes Credential für diese Anfrage.',
            severity: 'HIGH',
            learnMoreUrl: 'https://mitch.example/policies#NO_CREDENTIAL',
            actions: [
                { id: 'act_load', label: 'Credential laden', type: 'LOAD_CREDENTIAL', requiresConfirm: false },
                { id: 'act_manual', label: 'Manuell eingeben', type: 'MANUAL_ENTRY', requiresConfirm: true }
            ]
        },
        'ATTRIBUTE_BLOCKED': {
            reasonCode: 'ATTRIBUTE_BLOCKED',
            title: 'Daten-Minimierung',
            message: 'Der Service fragt zu viele Daten ab. Policy erlaubt dies nicht.',
            severity: 'HIGH',
            learnMoreUrl: 'https://mitch.example/policies#MINIMIZATION',
            actions: [
                { id: 'act_contact', label: 'Anbieter kontaktieren', type: 'CONTACT_VERIFIER', requiresConfirm: false }
            ]
        },
        'FRESHNESS_EXPIRED': {
            reasonCode: 'FRESHNESS_EXPIRED',
            title: 'Nachweis abgelaufen',
            message: 'Dein Credential ist zu alt. Bitte aktualisieren.',
            severity: 'WARN',
            learnMoreUrl: 'https://mitch.example/policies#FRESHNESS',
            actions: [
                { id: 'act_refresh', label: 'Jetzt aktualisieren', type: 'LOAD_CREDENTIAL', requiresConfirm: false }
            ]
        },
        'UNTRUSTED_ISSUER': {
            reasonCode: 'UNTRUSTED_ISSUER',
            title: 'Herausgeber nicht vertrauenswürdig',
            message: 'Der Aussteller deines Credentials ({issuer}) wird von der Policy nicht akzeptiert.',
            severity: 'CRITICAL',
            learnMoreUrl: 'https://mitch.example/policies#TRUST',
            actions: [
                { id: 'act_report', label: 'Problem melden', type: 'REPORT_ISSUE', requiresConfirm: false }
            ]
        },
        'NO_MATCHING_RULE': {
            reasonCode: 'NO_MATCHING_RULE',
            title: 'Zugriff blockiert',
            message: 'Keine Policy erlaubt diese Interaktion.',
            severity: 'HIGH',
            learnMoreUrl: 'https://mitch.example/policies#DEFAULT_DENY',
            actions: [
                { id: 'act_support', label: 'Hilfe', type: 'LEARN_MORE', requiresConfirm: false }
            ]
        },
        'CONSENT_REQUIRED': {
            reasonCode: 'CONSENT_REQUIRED',
            title: 'Zustimmung erforderlich',
            message: 'Deine ausdrückliche Zustimmung wird benötigt.',
            severity: 'WARN',
            learnMoreUrl: 'https://mitch.example/policies#CONSENT',
            actions: [] // Handled by PROMPT flow usually, but listed for completeness
        },
        'POLICY_MISMATCH': {
            reasonCode: 'POLICY_MISMATCH',
            title: 'Policy Konflikt',
            message: 'Anfrage entspricht nicht den Sicherheitsregeln.',
            severity: 'HIGH',
            actions: [{ id: 'act_learn', label: 'Details', type: 'LEARN_MORE', requiresConfirm: false }]
        },
        'CLAIM_NOT_ALLOWED': { // Aliased
            reasonCode: 'CLAIM_NOT_ALLOWED',
            title: 'Daten blockiert',
            message: 'Spezifische Datenfelder wurden blockiert.',
            severity: 'HIGH',
            actions: [{ id: 'act_contact', label: 'Kontakt', type: 'CONTACT_VERIFIER', requiresConfirm: false }]
        },
        'CREDENTIAL_EXPIRED': { // Aliased
            reasonCode: 'CREDENTIAL_EXPIRED',
            title: 'Abgelaufen',
            message: 'Credential ist abgelaufen.',
            severity: 'WARN',
            actions: [{ id: 'act_renew', label: 'Erneuern', type: 'LOAD_CREDENTIAL', requiresConfirm: false }]
        }
    };
}
