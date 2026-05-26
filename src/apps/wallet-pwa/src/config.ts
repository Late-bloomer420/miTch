export const CONFIG = {
    // T-36: Application Configuration
    VERIFIER_ENDPOINT: import.meta.env?.VITE_VERIFIER_URL || 'http://localhost:3004/present',
    ISSUER_ENDPOINT: import.meta.env?.VITE_ISSUER_URL || 'http://localhost:3005/credential',
    ISSUER_DID: import.meta.env?.VITE_ISSUER_DID || 'did:web:localhost%3A3005',
    TSL_URL: import.meta.env?.VITE_TSL_URL || 'http://localhost:3005/v1/eudi-lotl.json',
    DEMO_MODE: import.meta.env?.REACT_APP_DEMO_MODE !== 'false', // Default to true for PoC
};
