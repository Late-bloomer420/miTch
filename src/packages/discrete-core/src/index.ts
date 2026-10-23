export {
  Relation,
  type RelationPair,
} from './relation.js';

export {
  Mapping,
  MappingError,
  compose,
  inverse,
  bijectionWitness,
  type MappingErrorCode,
} from './mapping.js';

export {
  findDuplicateKeys,
  analyzeComposition,
  verifyBijectionPair,
  verifyTrustEquivalence,
  type DuplicateKeyFinding,
  type MappingProperties,
  type CompositionAnalysis,
  type BijectionVerification,
  type TrustLevel,
} from './mitc-applications.js';
