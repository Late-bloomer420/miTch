export {
    ConsentElement,
    defineConsentElement,
    CONSENT_ELEMENT_TAG,
    CONSENT_EVENT,
    CONSENT_CANCEL_EVENT,
} from './consent-element';
export { fromPolicyDecision, type FromPolicyDecisionInput } from './policy-adapter';
export { buildConsentReceipt } from './receipt';
export { DEFAULT_THEME, mergeTheme } from './theme';
export { DEFAULT_STRINGS_EN, DEFAULT_STRINGS_DE, stringsForLang } from './i18n';
export type {
    ClaimItem,
    ClaimPolicyState,
    ConsentReceipt,
    ConsentRequest,
    ConsentResult,
    ConsentStrings,
    ConsentTheme,
    ConsentVerdict,
    PredicateItem,
    VerifierIdentity,
} from './types';
