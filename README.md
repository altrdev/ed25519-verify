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
- **Generate** a random key pair with one click, handy for trying things out.
- **Clear input errors**: a malformed key or signature is explained next to the field ("expected 32 bytes, got 31",
  "not valid base64", "it looks like hex: switch the encoding") instead of being reported as a wrong signature.
- Messages as **text, hex or base64**, so binary payloads can be signed and verified as well.
- Keys in **PEM, OpenSSH or JWK** pasted as they are (detected automatically), or as plain hex / base64.
- Signatures in **hex or base64** (your choice is remembered). Base64 may be URL-safe, unpadded or wrapped over several lines.
- Private key hidden by default, one-click **copy** for private and public keys and for signatures.
- Light and dark theme, responsive layout, installable as a **PWA** (assets are precached by a service worker).

## Input formats

| Field | Format |
| --- | --- |
| Message | Plain text (signed as UTF-8 bytes), or raw bytes written in hex or base64. Empty messages are allowed |
| Public key | 32 bytes in hex or base64, or a key pasted as it is in a standard format: PEM (`BEGIN PUBLIC KEY`), OpenSSH (`ssh-ed25519 AAAA…`) or JWK |
| Private key | 32-byte seed in hex or base64 (the 64-byte NaCl/libsodium form, seed followed by public key, is accepted too: the seed is used), or PEM PKCS#8 (`BEGIN PRIVATE KEY`), an unencrypted OpenSSH private key (`BEGIN OPENSSH PRIVATE KEY`) or a JWK |
| Signature | 64 bytes, hex or base64 |

**Keys in other formats are recognised by themselves**, whatever encoding is selected: paste the content of the file and a
"Detected format" note appears under the field. A public key field also accepts a private JWK or OpenSSH private key (it
contains the public part). Keys of another type (RSA, EC, X25519, Ed448...) and keys protected by a passphrase are refused with
a message that says so; to use an encrypted key, remove the passphrase first (`ssh-keygen -p -f key`, or
`openssl pkey -in key.pem -out plain.pem`).

Signatures are checked with the strict rules of RFC 8032 / FIPS 186-5 (not the more permissive ZIP215 rules), so
"valid" means that a standards-compliant verifier agrees. In the rare case of a signature that fails the strict check
but would be accepted under ZIP215 (used by some consensus systems, e.g. Zcash), the result says so instead of just "wrong".

The Hex / Base64 selector at the top of each tab applies to keys and signatures. The message has its own
Text / Hex / Base64 selector, so you can sign and verify binary data (hashes, already encoded payloads) too.

## Privacy

Signing and verification use [@noble/ed25519](https://github.com/paulmillr/noble-ed25519) in your browser and the app makes no
requests with your data. The page ships a strict [Content-Security-Policy](src/csp.ts) (same-origin requests only, no inline scripts),
so the browser itself refuses any request the page tries to make to another site. Even so, treat any web page with care: do not paste production private keys into tools you have not audited,
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

## Contributing

Issues and pull requests are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). Tagged versions are listed under
[Releases](https://github.com/altrdev/ed25519-verify/releases).

## License

[MIT](LICENSE) © Alessandro Travi
