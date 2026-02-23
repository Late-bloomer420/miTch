export interface PredicateRule {
  name: string;
  allowed: boolean;
}

export interface PolicyManifestV0 {
  version: "v0";
  id: string;
  purposes: string[];
  predicates: PredicateRule[];
  failClosed: boolean;
}
