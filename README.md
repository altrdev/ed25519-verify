# Ed25519 signature tools

[![Build and Deploy](https://github.com/altrdev/ed25519-verify/actions/workflows/deploy-to-gh-pages.yml/badge.svg)](https://github.com/altrdev/ed25519-verify/actions/workflows/deploy-to-gh-pages.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Verify and create [Ed25519](https://ed25519.cr.yp.to/) signatures straight from your browser.
Paste a public key, a message and a signature to check them, or sign a message with a private key.
Everything runs client-side: **nothing is uploaded anywhere**.

**Live demo: <https://ed25519.altr.dev/>**

<p align="center">
  <img src="docs/screenshot-light.png" alt="Verifying a signature, light theme" width="49%">
  <img src="docs/screenshot-dark.png" alt="Signing a message, dark theme" width="49%">
</p>

## Features

- **Verify** a signature given a public key and a message, with a clear valid / wrong result.
- **Sign** a message with a private key; the public key is deduced and shown next to it.
- Keys and signatures in **hex or base64** (your choice is remembered).
- Private key hidden by default, one-click **copy** for signatures and public keys.
- Light and dark theme, responsive layout, installable as a **PWA** (assets are precached by a service worker).

## Input formats

| Field | Format |
| --- | --- |
| Message | Plain text, signed and verified as UTF-8 bytes |
| Public key | 32 bytes, hex or base64 |
| Private key | 32-byte seed, hex or base64. The 64-byte NaCl/libsodium form (seed followed by public key) is accepted too: the seed is used |
| Signature | 64 bytes, hex or base64 |

The Hex / Base64 selector applies to keys and signatures, not to the message.

## Privacy

Signing and verification use [noble-ed25519](https://github.com/paulmillr/noble-ed25519) in your browser and the app makes no
requests with your data. Even so, treat any web page with care: do not paste production private keys into tools you have not audited,
and prefer throwaway keys for testing. The source is small enough to read.

## Development

Requires Node.js 22 or newer.

```bash
npm install
npm run dev        # dev server with hot reload
npm test           # unit and component tests (Vitest + Testing Library)
npm run build      # type-check and production build in dist/
npm run preview    # serve the production build locally
```

Stack: [Preact](https://preactjs.com) with [@preact/signals](https://preactjs.com/guide/v10/signals/),
[Vite](https://vitejs.dev), [Vitest](https://vitest.dev) and [vite-plugin-pwa](https://vite-pwa-org.netlify.app/).

```
src/
  signature.ts      Ed25519 wrapper (hex/base64 conversion, sign, verify, public key)
  store.ts          theme and encoding preferences (signals, persisted in localStorage)
  App.tsx           page shell, tabs, theme toggle
  FormVerify.tsx    verify tab
  FormSign.tsx      sign tab
  __tests__/        tests
```

### Deployment

Every push to `main` is tested, built and published to GitHub Pages by
[`.github/workflows/deploy-to-gh-pages.yml`](.github/workflows/deploy-to-gh-pages.yml).
In the repository settings, **Pages → Source** must be set to **GitHub Actions**.

## License

[MIT](LICENSE) © Alessandro Travi
