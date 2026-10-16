# Ed25519 signature tools

Small web app (PWA) to **verify** and **create** Ed25519 signatures, with keys and signatures in hex or base64.
Everything runs in the browser: nothing is sent to any server.

> Even so, avoid pasting production private keys into any web page.

Keys in the 64-byte NaCl/libsodium format (seed + public key) are accepted too: the seed is used.

## Stack

[Preact](https://preactjs.com) + [@preact/signals](https://preactjs.com/guide/v10/signals/), [Vite](https://vitejs.dev),
[Vitest](https://vitest.dev) + Testing Library, [noble-ed25519](https://github.com/paulmillr/noble-ed25519), `vite-plugin-pwa`.

## Development

```bash
npm install
npm run dev        # dev server
npm test           # unit + component tests
npm run build      # type-check and production build in dist/
npm run preview    # serve the production build
```

Pushes to `main` are tested, built and deployed to GitHub Pages by `.github/workflows/deploy-to-gh-pages.yml`
(repository Settings → Pages → Source must be **GitHub Actions**).
