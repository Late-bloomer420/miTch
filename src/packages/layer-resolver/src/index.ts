/**
 * @package @mitch/layer-resolver
 * @description Protection Layer Resolution and Enforcement
 *
 * miTch implements a layer-based protection model where higher layers
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
 * Determine the minimum required layer for a given data type.
 *
 * @param dataType - The type of data being processed
 * @returns Minimum required protection layer
 *
 * @example
 * ```typescript
 * getMinimumLayerForData('age'); // Returns: ProtectionLayer.GRUNDVERSORGUNG
 * getMinimumLayerForData('healthRecord'); // Returns: ProtectionLayer.VULNERABLE
 * ```
 */
export function getMinimumLayerForData(dataType: string): ProtectionLayer {
  // Map data types to minimum required layers
  const layerMap: Record<string, ProtectionLayer> = {
    // Layer 0 (WELT) - Universal
    consent: ProtectionLayer.WELT,
    publicKey: ProtectionLayer.WELT,

    // Layer 1 (GRUNDVERSORGUNG) - Children + Basic
    age: ProtectionLayer.GRUNDVERSORGUNG,
    birthDate: ProtectionLayer.GRUNDVERSORGUNG,
    education: ProtectionLayer.GRUNDVERSORGUNG,

    // Layer 2 (VULNERABLE) - Sensitive Adult Data
    healthRecord: ProtectionLayer.VULNERABLE,
    medicalHistory: ProtectionLayer.VULNERABLE,
    prescription: ProtectionLayer.VULNERABLE,
    financialData: ProtectionLayer.VULNERABLE,
    bankAccount: ProtectionLayer.VULNERABLE,
    creditScore: ProtectionLayer.VULNERABLE,
    employmentRecord: ProtectionLayer.VULNERABLE,
    professionalLicense: ProtectionLayer.VULNERABLE,
  };

  return layerMap[dataType] ?? ProtectionLayer.WELT;
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
};
