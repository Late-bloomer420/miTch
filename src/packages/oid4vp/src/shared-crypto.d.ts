declare module '@mitch/shared-crypto' {
    import type { JWK } from 'jose';

    export interface CNFClaim {
        jwk?: JWK;
    }

    export interface StatusClaim {
        status_list: {
            idx: number;
            uri: string;
        };
    }

    export interface SDJWTVCPayload {
        iss: string;
        vct: string;
        iat: number;
        exp?: number;
        nbf?: number;
        sub?: string;
        cnf?: CNFClaim;
        status?: StatusClaim;
        _sd?: string[];
        _sd_alg?: string;
        [key: string]: unknown;
    }

    export interface SDJWTVCValidationResult {
        ok: boolean;
        payload?: SDJWTVCPayload;
        errors: string[];
    }

    export interface KeyBindingValidationResult {
        ok: boolean;
        payload?: {
            aud: string;
            nonce: string;
            iat: number;
            sd_hash: string;
        };
        errors: string[];
    }

    export function issueSDJWTVC(payload: SDJWTVCPayload, issuerPrivateKey: CryptoKey): Promise<string>;
    export function validateSDJWTVC(sdJwt: string, issuerPublicKey: CryptoKey): Promise<SDJWTVCValidationResult>;
    export function createKeyBindingJWT(
        opts: { aud: string; nonce: string; sdJwtWithDisclosures: string },
        holderPrivateKey: CryptoKey
    ): Promise<string>;
    export function validateKeyBindingJWT(
        kbJwt: string,
        holderJWK: JWK,
        opts: {
            expectedAud: string;
            expectedNonce: string;
            sdJwtWithDisclosures: string;
            maxAgeSeconds?: number;
        }
    ): Promise<KeyBindingValidationResult>;
    export function buildCNFClaim(holderPublicKey: CryptoKey): Promise<CNFClaim>;
}
