/**
 * Reusable StatusList2021 test fixtures (S2-05).
 *
 * Shared builders so multiple runtime test surfaces (this package's own tests,
 * `@askmi/integration-tests`, the verifier-demo backend, ...) construct the same
 * status-list fixtures without copy/pasting the object shells.
 *
 * Intentionally pure data builders — no test framework import, so this module can
 * ship in the package's `dist` and be imported across packages. Encoding of the
 * bitstring (`encodedList`) is left to each caller, so no caller's revocation
 * semantics change: `makeStatusListCredential` takes the already-encoded string.
 */
import type { StatusListCredential, StatusListEntry } from './types';

/** Default status-list URL used by the existing fixtures. */
export const TEST_STATUS_LIST_URL = 'https://example.com/status-list/1';

/** Default issuer DID used by the existing fixtures. */
export const TEST_STATUS_LIST_ISSUER = 'did:example:issuer';

/**
 * Build a StatusList2021Entry referencing a status-list credential.
 * Signature is `(index, url)` to match the existing majority convention.
 */
export function makeStatusListEntry(
  index: number | string = 0,
  url: string = TEST_STATUS_LIST_URL,
): StatusListEntry {
  return {
    id: `${url}#${index}`,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: String(index),
    statusListCredential: url,
  };
}

/**
 * Build a StatusList2021Credential shell around an already-encoded bitstring.
 * The caller supplies `encodedList`, so revocation/encoding semantics stay local.
 */
export function makeStatusListCredential(options: {
  encodedList: string;
  url?: string;
  issuer?: string;
  statusPurpose?: 'revocation' | 'suspension';
}): StatusListCredential {
  const url = options.url ?? TEST_STATUS_LIST_URL;
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: url,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: options.issuer ?? TEST_STATUS_LIST_ISSUER,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: `${url}#list`,
      type: 'StatusList2021',
      statusPurpose: options.statusPurpose ?? 'revocation',
      encodedList: options.encodedList,
    },
  };
}
