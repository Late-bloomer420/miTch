// Build-time selection: query parameters cannot switch storage environments.
export const isDemoRuntime = import.meta.env?.MODE === 'demo';
export const demoWalletOrigin = 'http://localhost:5184';
export const walletDatabaseName = isDemoRuntime ? 'askmi_demo_wallet_v1' : 'mitch_wallet_v1';
export const holderDatabaseName = isDemoRuntime
  ? 'askmi_demo_holder_keys_v1'
  : 'mitch_holder_keys_v1';

export function runtimeOriginAllowed(origin: string, demo = isDemoRuntime): boolean {
  return !demo || origin === demoWalletOrigin;
}

export function walletRoute(search: string): 'wallet' | 'landing' | 'invalid' {
  const params = new URLSearchParams(search);
  if (['state', 'nonce', 'request_uri'].some((key) => params.has(key))) {
    if (!params.get('state') || !params.get('nonce') || !params.get('request_uri'))
      return 'invalid';
    return 'wallet';
  }
  if (
    params.get('demo') === 'wallet' ||
    ['endpoint', 'scenario', 'sessionId'].every((key) => params.get(key))
  )
    return 'wallet';
  return 'landing';
}
