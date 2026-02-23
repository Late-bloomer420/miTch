export interface SecurityConfig {
  clockSkewSeconds: number;
  nonceTtlSeconds: number;
}

export const securityConfig: SecurityConfig = {
  clockSkewSeconds: 90,
  nonceTtlSeconds: 600,
};
