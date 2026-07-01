/**
 * @package @askmi/layer-resolver
 * @description Protection Layer Resolution and Enforcement
 *
 * AskMI implements a layer-based protection model where higher layers
 * inherit protections from lower layers. This package provides the
 * core enum and utilities for layer-aware policy decisions.
 */

/**
 * Protection Layers in ascending order of restriction.
 *
 * Each layer represents a category of data subjects and their
 * protection requirements. Higher layers inherit all protections
 * from lower layers.
 *
 * @example
 * ```typescript
 * // A service operating at Layer 2 must also comply with Layer 0 and Layer 1 rules
 * const serviceLayer = ProtectionLayer.VULNERABLE;
 * const mustComplyWith = [
 *   ProtectionLayer.WELT,
 *   ProtectionLayer.GRUNDVERSORGUNG,
 *   ProtectionLayer.VULNERABLE
 * ];
 * ```
 */
export enum ProtectionLayer {
  /**
   * Layer 0: WELT (World) - Universal Principles
   *
   * Global rules that apply to ALL data subjects and services.
   *
   * Core Principles:
   * - Rule over Authority
   * - Data Minimization by Construction
   * - User Sovereignty
   * - Non-Linkability
   * - EU-First Trust
   *
   * Never Events (apply globally):
   * - No central profiles
   * - No cross-service tracking
   * - No data commercialization
   * - No commercialization of fundamental rights (Grundrechten)
   *
   * **Binding:** Policy Manifest Section 1 & 4
   */
  WELT = 0,

  /**
   * Layer 1: GRUNDVERSORGUNG (Basic Services) - Children + Essential Services
   *
   * Enhanced protections for minors and basic life necessities.
   *
   * Protected Categories:
   * - Children (under 18)
   * - Basic authentication (age verification)
   * - Essential service access
   *
   * Additional Protections (beyond Layer 0):
   * - Stricter consent requirements
   * - No behavioral profiling for minors
   * - Mandatory crypto-shredding for all transactions
   * - No monetization of children's data (Policy Manifest Section 4)
   *
   * Use Cases:
   * - Age verification (18+, 16+, etc.)
   * - School/education credentials
   * - Basic identity proofs
   *
   * **Binding:** Policy Manifest + Layer 0 inheritance
   */
  GRUNDVERSORGUNG = 1,

  /**
   * Layer 2: ERWACHSENE-VULNERABLE (Adults-Vulnerable) - Health, Elderly, Finance
   *
   * Maximum protection for sensitive adult data categories.
   *
   * Protected Categories:
   * - Health records (EHDS)
   * - Financial data
   * - Elderly/disability services
   * - Employment/professional credentials
   *
   * Additional Protections (beyond Layer 0 & 1):
   * - Mandatory encryption at rest and in transit
   * - Enhanced audit trails (medical consent documentation)
   * - Specialized revocation mechanisms
   * - Sector-specific compliance (GDPR Art. 9 Special Categories)
   *
   * Use Cases:
   * - EHDS patient summaries
   * - Emergency health access
   * - Financial KYC
   * - Professional license verification
   *
   * **Binding:** GDPR Art. 9 + EHDS Regulation + Layer 0 & 1 inheritance
   */
  VULNERABLE = 2,
}

/**
 * Get all layers that must be complied with for a given operation layer.
 *
 * @param layer - The layer at which the operation is being performed
 * @returns Array of layers that must be checked (from base to target)
 *
 * @example
 * ```typescript
 * getInheritedLayers(ProtectionLayer.VULNERABLE);
 * // Returns: [ProtectionLayer.WELT, ProtectionLayer.GRUNDVERSORGUNG, ProtectionLayer.VULNERABLE]
 * ```
 */
export function getInheritedLayers(layer: ProtectionLayer): ProtectionLayer[] {
  const layers: ProtectionLayer[] = [];
  for (let i = ProtectionLayer.WELT; i <= layer; i++) {
    layers.push(i);
  }
  return layers;
}

/**
 * Check if a given layer includes another layer's protections.
 *
 * @param operationLayer - The layer being operated at
 * @param requiredLayer - The layer whose protections must be checked
 * @returns true if operationLayer includes requiredLayer protections
 *
 * @example
 * ```typescript
 * includesLayer(ProtectionLayer.VULNERABLE, ProtectionLayer.WELT);
 * // Returns: true (Layer 2 includes Layer 0 protections)
 *
 * includesLayer(ProtectionLayer.GRUNDVERSORGUNG, ProtectionLayer.VULNERABLE);
 * // Returns: false (Layer 1 does NOT include Layer 2 protections)
 * ```
 */
export function includesLayer(
  operationLayer: ProtectionLayer,
  requiredLayer: ProtectionLayer
): boolean {
  return operationLayer >= requiredLayer;
}

/**
 * Get human-readable name for a protection layer.
 *
 * @param layer - The protection layer
 * @returns Localized name (German/English)
 */
export function getLayerName(layer: ProtectionLayer): string {
  switch (layer) {
    case ProtectionLayer.WELT:
      return 'WELT (World) - Universal Principles';
    case ProtectionLayer.GRUNDVERSORGUNG:
      return 'GRUNDVERSORGUNG (Basic Services) - Children + Essentials';
    case ProtectionLayer.VULNERABLE:
      return 'ERWACHSENE-VULNERABLE (Adults-Vulnerable) - Health, Elderly, Finance';
    default:
      return `Unknown Layer ${layer}`;
  }
}

/**
 * Neutral sensitivity view over a protection layer. NOT a risk score —
 * a structural projection of the layer the policy engine resolved.
 */
export type Sensitivity = 'low' | 'medium' | 'high' | 'unclassified';

/**
 * ENFORCEMENT map — claim/data type → minimum protection layer. Drives
 * getMinimumLayerForData and therefore the policy-engine's layer check.
 * Extending this map changes access-control verdicts; every legitimate rule
 * for newly classified VULNERABLE claims must opt into that layer explicitly.
 */
const LAYER_MAP: Record<string, ProtectionLayer> = {
  // Layer 0 (WELT) — Universal
  consent: ProtectionLayer.WELT,
  publicKey: ProtectionLayer.WELT,

  // Layer 1 (GRUNDVERSORGUNG) — Children + Basic
  age: ProtectionLayer.GRUNDVERSORGUNG,
  dateOfBirth: ProtectionLayer.GRUNDVERSORGUNG,
  education: ProtectionLayer.GRUNDVERSORGUNG,

  // Layer 2 (VULNERABLE) — Sensitive Adult Data
  healthRecord: ProtectionLayer.VULNERABLE,
  medicalHistory: ProtectionLayer.VULNERABLE,
  prescription: ProtectionLayer.VULNERABLE,
  bloodGroup: ProtectionLayer.VULNERABLE,
  allergies: ProtectionLayer.VULNERABLE,
  activeProblems: ProtectionLayer.VULNERABLE,
  emergencyContacts: ProtectionLayer.VULNERABLE,
  medication: ProtectionLayer.VULNERABLE,
  dosageInstruction: ProtectionLayer.VULNERABLE,
  refillsRemaining: ProtectionLayer.VULNERABLE,
  financialData: ProtectionLayer.VULNERABLE,
  bankAccount: ProtectionLayer.VULNERABLE,
  creditScore: ProtectionLayer.VULNERABLE,
  employmentRecord: ProtectionLayer.VULNERABLE,
  professionalLicense: ProtectionLayer.VULNERABLE,
  role: ProtectionLayer.VULNERABLE,
  licenseId: ProtectionLayer.VULNERABLE,
};

/**
 * VISIBILITY map — the enforcement map PLUS the concrete claim vocabulary used
 * in real flows, for the user-facing sensitivity view ONLY. Built as a superset
 * of LAYER_MAP so there is one shared base in one file (single authority).
 * Visibility-only vocabulary can be added here only when it must not affect
 * enforcement verdicts.
 */
const VISIBILITY_LAYER_MAP: Record<string, ProtectionLayer> = {
  ...LAYER_MAP,
  // Identity basics
  given_name: ProtectionLayer.WELT,
  family_name: ProtectionLayer.WELT,
  birth_date: ProtectionLayer.GRUNDVERSORGUNG,
};

/**
 * Determine the minimum required layer for a given data type.
 * ENFORCEMENT path — keeps the safe WELT default for unmapped types.
 *
 * @example
 * ```typescript
 * getMinimumLayerForData('age'); // Returns: ProtectionLayer.GRUNDVERSORGUNG
 * getMinimumLayerForData('healthRecord'); // Returns: ProtectionLayer.VULNERABLE
 * ```
 */
export function getMinimumLayerForData(dataType: string): ProtectionLayer {
  return LAYER_MAP[dataType] ?? ProtectionLayer.WELT;
}

/**
 * VISIBILITY path — returns the claim's protection layer, or `undefined`
 * when the claim is not classified. Unlike getMinimumLayerForData this does
 * NOT default to WELT, so the UI can honestly show "unclassified" instead of
 * a false "low". Reads VISIBILITY_LAYER_MAP (enforcement base + demo vocabulary).
 */
export function resolveLayerForData(dataType: string): ProtectionLayer | undefined {
  return VISIBILITY_LAYER_MAP[dataType];
}

/** Project a protection layer onto a neutral sensitivity view (no scoring). */
export function sensitivityFromLayer(
  layer: ProtectionLayer | undefined | null
): Sensitivity {
  switch (layer) {
    case ProtectionLayer.WELT:
      return 'low';
    case ProtectionLayer.GRUNDVERSORGUNG:
      return 'medium';
    case ProtectionLayer.VULNERABLE:
      return 'high';
    default:
      return 'unclassified';
  }
}

/** Convenience: claim name → neutral sensitivity view. */
export function sensitivityForData(dataType: string): Sensitivity {
  return sensitivityFromLayer(resolveLayerForData(dataType));
}

/**
 * Export all types and utilities
 */
export default {
  ProtectionLayer,
  getInheritedLayers,
  includesLayer,
  getLayerName,
  getMinimumLayerForData,
  resolveLayerForData,
  sensitivityFromLayer,
  sensitivityForData,
};
