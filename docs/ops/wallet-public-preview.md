# Wallet Public Preview

Use this flow when a phone needs to test the wallet outside the local network.

```powershell
pnpm run preview:wallet:public
```

The script:

- builds `@askmi/wallet-pwa`;
- starts Vite preview on `http://127.0.0.1:4173` with `ASKMI_DEV_HTTPS=0`;
- downloads `cloudflared.exe` to `%TEMP%` if needed;
- creates a temporary `trycloudflare.com` tunnel;
- prints the public wallet URL with `?demo=wallet`.

Keep the terminal open while testing. Press `Ctrl+C` to stop both the preview server
and the Cloudflare tunnel.

Why preview instead of Vite dev server:

- the Vite dev server can return HTTP 200 through Cloudflare while rendering a blank
  page because the dev client/HMR path is not stable through the quick tunnel;
- the production preview serves the built app and is the phone-demo path to use.

Useful flags:

```powershell
.\scripts\wallet-public-preview.ps1 -NoBuild
.\scripts\wallet-public-preview.ps1 -PreviewPort 4174
.\scripts\wallet-public-preview.ps1 -Detach
```
