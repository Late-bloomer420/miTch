# @mitch/layer-resolver

**Protection Layer Resolution and Enforcement**

This package provides the core layer enumeration and utilities for miTch's layer-based protection model.

## Protection Layers

miTch implements three protection layers in ascending order:

### Layer 0: WELT (World) - Universal Principles
Global rules that apply to ALL data subjects and services.

**Core Principles:**
- Rule over Authority
- Data Minimization by Construction
- User Sovereignty
- Non-Linkability
- EU-First Trust

**Never Events (global):**
- ❌ No central profiles
- ❌ No cross-service tracking
- ❌ No data commercialization
- ❌ No commercialization of fundamental rights

### Layer 1: GRUNDVERSORGUNG (Basic Services) - Children + Essentials
Enhanced protections for minors and basic life necessities.

**Protected Categories:**
- Children (under 18)
- Basic authentication (age verification)
- Essential service access

**Additional Protections:**
- Stricter consent requirements
- No behavioral profiling for minors
- Mandatory crypto-shredding
- No monetization of children's data

### Layer 2: ERWACHSENE-VULNERABLE (Adults-Vulnerable) - Health, Elderly, Finance
Maximum protection for sensitive adult data categories.

**Protected Categories:**
- Health records (EHDS)
- Financial data
- Elderly/disability services
- Professional credentials

**Additional Protections:**
- Mandatory encryption at rest and in transit
- Enhanced audit trails
- Specialized revocation mechanisms
- GDPR Art. 9 compliance (Special Categories)

## Usage

```typescript
import {
  ProtectionLayer,
  getInheritedLayers,
  includesLayer,
  getMinimumLayerForData
} from '@mitch/layer-resolver';

// Determine required layer for data type
const layer = getMinimumLayerForData('healthRecord');
// Returns: ProtectionLayer.VULNERABLE (2)

// Get all layers that must be checked
const layers = getInheritedLayers(ProtectionLayer.VULNERABLE);
// Returns: [ProtectionLayer.WELT, ProtectionLayer.GRUNDVERSORGUNG, ProtectionLayer.VULNERABLE]

// Check if a layer includes another's protections
if (includesLayer(ProtectionLayer.VULNERABLE, ProtectionLayer.GRUNDVERSORGUNG)) {
  console.log('Layer 2 includes Layer 1 protections ✓');
}
```

## Integration with Policy Engine

```typescript
import { PolicyEngine } from '@mitch/policy-engine';
import { ProtectionLayer, getMinimumLayerForData } from '@mitch/layer-resolver';

const engine = new PolicyEngine();

// Evaluate request with layer awareness
const result = engine.evaluate({
  verifierId: 'liquor-store',
  requestedData: ['age'],
  purpose: 'age_verification',
  minimumLayer: getMinimumLayerForData('age') // Layer 1
});
```

## API Reference

### `ProtectionLayer` (enum)
- `WELT = 0` - Universal principles
- `GRUNDVERSORGUNG = 1` - Children + basic services
- `VULNERABLE = 2` - Health, elderly, finance

### `getInheritedLayers(layer: ProtectionLayer): ProtectionLayer[]`
Returns array of all layers that must be complied with (from base to target).

### `includesLayer(operationLayer: ProtectionLayer, requiredLayer: ProtectionLayer): boolean`
Checks if operationLayer includes requiredLayer's protections.

### `getLayerName(layer: ProtectionLayer): string`
Returns human-readable name for a layer.

### `getMinimumLayerForData(dataType: string): ProtectionLayer`
Determines minimum required layer for a given data type.

## License

MIT - Part of miTch project
