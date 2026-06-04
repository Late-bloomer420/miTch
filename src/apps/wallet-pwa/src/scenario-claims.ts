/**
 * PoC scenario claims — hardcoded credential data per demo scenario.
 * In production, these would come from stored credentials in SecureStorage.
 *
 * Source of truth: `ASKMI_SCENARIO_CLAIMS` in `@askmi/shared-types`. This module
 * re-exports it under the wallet's expected `Record<string, ...>` shape so the
 * wallet and the verifier-demo backend cannot drift apart on demo claim values.
 */
import { ASKMI_SCENARIO_CLAIMS } from '@askmi/shared-types';

export const SCENARIO_CLAIMS: Record<string, Record<string, unknown>> = ASKMI_SCENARIO_CLAIMS;
