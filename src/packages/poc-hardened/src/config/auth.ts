export interface AuthConfig {
  enabled: boolean;
  token: string;
  nextToken?: string;
}

export const authConfig: AuthConfig = {
  enabled: process.env.AUTH_TOKEN_REQUIRED === "1",
  token: process.env.AUTH_TOKEN ?? "",
  nextToken: process.env.AUTH_TOKEN_NEXT,
};

export function isAuthorized(headerValue: string | undefined): boolean {
  if (!authConfig.enabled) return true;
  if (!authConfig.token && !authConfig.nextToken) return false;
  if (!headerValue) return false;

  if (authConfig.token && headerValue === `Bearer ${authConfig.token}`) return true;
  if (authConfig.nextToken && headerValue === `Bearer ${authConfig.nextToken}`) return true;
  return false;
}
