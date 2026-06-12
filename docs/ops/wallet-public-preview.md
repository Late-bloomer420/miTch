# Wallet Public Preview

Use this flow when a phone needs to test the wallet outside the local network.

```powershell
pnpm run preview:wallet:public
```

The script:

- starts `@askmi/issuer-mock` on `127.0.0.1:3005`;
- starts `verifier-backend` on `127.0.0.1:3004`;
- creates temporary `trycloudflare.com` tunnels for issuer and verifier;
- builds `@askmi/wallet-pwa` with `VITE_ISSUER_URL` and `VITE_VERIFIER_URL`
  pointing at those public tunnels;
- starts Vite preview on `http://127.0.0.1:4173` with `ASKMI_DEV_HTTPS=0`;
- downloads `cloudflared.exe` to `%TEMP%` if needed;
- creates a temporary `trycloudflare.com` tunnel for the wallet preview;
- prints the public wallet URL with `?demo=wallet`.

Keep the terminal open while testing. Press `Ctrl+C` to stop both the preview server
and the Cloudflare tunnel.

Why preview instead of Vite dev server:

- the Vite dev server can return HTTP 200 through Cloudflare while rendering a blank
  page because the dev client/HMR path is not stable through the quick tunnel;
- the production preview serves the built app and is the phone-demo path to use.
- the phone cannot call `localhost:3004` or `localhost:3005` on the dev machine,
  so the public preview must tunnel issuer and verifier too.

Useful flags:

```powershell
.\scripts\wallet-public-preview.ps1 -NoBuild
.\scripts\wallet-public-preview.ps1 -PreviewPort 4174
.\scripts\wallet-public-preview.ps1 -Detach
```
