# Contributing

Thanks for your interest in Ed25519 signature tools! Bug reports, ideas and pull requests are welcome.

## Reporting a problem or suggesting something

Open an [issue](https://github.com/altrdev/ed25519-verify/issues). For a bug, the most useful things are:

- what you did and what you expected to happen;
- the formats involved (of the key, the message and the signature);
- the app version (in the page footer) and the browser.

You can include a public key, a message and a signature to reproduce a verification problem. **Never paste a private key
you care about** in an issue. If you think you found a security problem, please do not post the details publicly:
follow [SECURITY.md](SECURITY.md) and report it privately.

## Setting up

You need Node.js 22 or newer.

```bash
git clone https://github.com/altrdev/ed25519-verify.git
cd ed25519-verify
npm install
npm run dev        # dev server with hot reload
```

| Command | What it does |
| --- | --- |
| `npm test` | Runs the tests once (Vitest + Testing Library) |
| `npm run test:watch` | Runs the tests on every change |
| `npm run typecheck` | TypeScript check without emitting files |
| `npm run test:e2e` | End-to-end and accessibility tests ([Playwright](https://playwright.dev/) + axe) against the production build: run `npm run build` first, and `npx playwright install chromium` once |
| `npm run lint` | Checks formatting and lint rules with [Biome](https://biomejs.dev/) (what CI runs) |
| `npm run format` | Fixes formatting and the lint problems that have a safe fix |
| `npm run build` | Type-check and production build in `dist/` |
| `npm run preview` | Serves the production build locally |

## Making a change

1. Create a branch from `main`.
2. Make the change, with tests (see below).
3. Run `npm run format`, `npm run typecheck`, `npm test` and `npm run build`: all must pass (`npm run lint` is the check CI makes).
4. Open a pull request against `main` explaining what changed and why. The [CI](.github/workflows/ci.yml) workflow runs the
   same three commands on every pull request, so you will see a red check if something is broken.

Commit messages in this repository look like `[feat]: short description`, `[fix]: ...`, `[chore]: ...`. Keep the first line short and
use the body for the reasoning when it is not obvious.

### Where things live

```
src/
  signature.ts      all the cryptography, input parsing and validation (no UI)
  codecs.ts         hex, base64, base58, base32 and byte-array codecs, and how a pasted text can be read
  keyformats.ts     parsers for keys pasted as PEM (PKCS#8 / SPKI), OpenSSH or JWK (no UI, no dependencies)
  ecosystems.ts     did:key, Stellar, Tor onion, NEAR and Solana keys, read and written (checked against an independent implementation)
  sha3.ts           SHA3-256, only for the onion checksum
  share.ts          the share link: what the Verify tab holds, in the URL fragment
  jws.ts            JWS / JWT (EdDSA): parsing, what is refused and why, building a token; JwsPanel.tsx and FormSigned.tsx are its screen
  sshsig.ts         SSH signatures (ssh-keygen -Y): parsing, the structure that is signed, signing; SshsigPanel.tsx is its screen
  minisign.ts       minisign: the public key and signature files, what is signed, signing; MinisignPanel.tsx is its screen
  blake2b.ts        BLAKE2b-512, for minisign (checked against OpenSSL)
  files.ts          reading a key / signature file into a field, and saving one (names, binary keys, size limit)
  examples.ts      the RFC 8032 vectors (and a ZIP215 case) behind "Load example", checked against the library by the tests
  diagnose.ts      hints for a wrong signature: certain facts, and retries that make it valid
  keyfiles.ts       the opposite direction: writes keys as PEM, OpenSSH or JWK (checked byte for byte against OpenSSL / ssh-keygen)
  FormatMenu.tsx    the format menu of a key / signature field (converts the text, or picks how a result is written)
  bytes.ts          hex and base64 helpers
  store.ts          theme and encoding preferences (signals, persisted in localStorage)
  App.tsx           page shell, tabs, theme toggle
  FormVerify.tsx    verify tab
  FormSign.tsx      sign tab
  Field.tsx, Banner.tsx, Segmented.tsx, ...   small UI building blocks
  __tests__/        tests
```

### Guidelines

- **Tests in two layers.** `src/__tests__` (Vitest, jsdom) covers the logic and the components; `e2e/` (Playwright) drives the built site in Chromium: verify and sign with RFC 8032 vectors, format conversion, share links, offline reload, no request to another host, and an [axe](https://github.com/dequelabs/axe-core) accessibility check of both tabs in both themes. A new screen or state should be added to `e2e/a11y.spec.ts`. If a Chromium is already installed, point `PLAYWRIGHT_CHROMIUM_PATH` to it.
- **Style is automatic.** Biome formats the code (4 spaces, single quotes, 140 columns) and lints it; `npm run format` fixes it. It replaces ESLint and Prettier on purpose: `typescript-eslint` does not support TypeScript 7 yet, and one tool is faster and simpler to keep. CSS is not covered.
- **Keep it client-side and dependency-light.** The app must never send keys, messages or signatures anywhere, and the
  bundle is small on purpose. Think twice before adding a dependency, especially in `signature.ts`.
- **Do not loosen the Content-Security-Policy** in `src/csp.ts` (it is injected into `index.html` by the production build, not in
  `npm run dev`). It only allows requests to the site's own origin and forbids any inline script, which is what makes "nothing is
  uploaded" enforceable.
  A change that needs a new source must say why in its pull request.
- **Keep the cryptography out of the components.** Parsing, validation and signing belong in `signature.ts`, where they are easy to test.
  Components only show what it returns.
- **Never read a text as another value.** Anything the app writes must read back to the same bytes, or be refused with a
  question (`choices`): a silent misreading means verifying with the wrong key. The tests check it for every format.
- **Be explicit about malformed input.** A malformed key or signature is an `InputError` shown next to the field. "Signature is wrong"
  is only for a well formed signature that does not match.
- **Verification is strict** (RFC 8032 / FIPS 186-5). Do not loosen it silently: `verdict()` reports when a signature would only pass
  under ZIP215.
- **Test what you change.** Logic goes in `src/__tests__/signature.test.ts` (with known vectors when possible), behaviour of the UI in
  the component tests. A bug fix starts with a test that fails.
- **Check both themes and a phone width** when you touch styles; colors are CSS variables in `src/style.css`.

## Dependencies

[Dependabot](.github/dependabot.yml) opens a pull request every week for outdated npm packages (minor and patch updates grouped
together, major ones on their own) and for the versions of the GitHub Actions used by the workflows. They go through the same CI
as any other pull request: read the release notes of a major update before merging it.

## Deployment and releases

Every pull request runs the checks of [`ci.yml`](.github/workflows/ci.yml) (lint, type-check, unit tests, build, CSP guard, end-to-end and
accessibility tests). The deploy and the release start by calling that same workflow, so there is one definition of "it works" and a
push that skipped the pull request is still checked before it ships.

**The website is what a release ships.** A push to `main` does not change it; merged work goes online with the next release.
This way the version in the page footer is exactly the code of that release, and a release is a decision, not a side effect of a merge.

Releases use [semantic versioning](https://semver.org/) and are made by [`release.yml`](.github/workflows/release.yml), started by hand
(maintainers): **Actions → Release → Run workflow** on `main`, choosing patch, minor or major. The workflow

1. runs all the checks (`ci.yml`);
2. works out the next version from the latest `vX.Y.Z` tag, and creates that tag on the commit it checked;
3. publishes the GitHub release (notes generated from the merged pull requests, the built site attached as a zip);
4. publishes the same version on GitHub Pages ([`deploy-to-gh-pages.yml`](.github/workflows/deploy-to-gh-pages.yml)).

The version is the tag: nothing is committed (so it works with a protected `main`) and there is no version in `package.json` to
bump, it is set to `0.0.0` on purpose. The build gets the version from the `APP_VERSION` variable that the workflow sets; a local
build says `dev`. Do not push `v*` tags by hand: they do nothing.

To publish a branch without releasing (an emergency, or a test), run **Build and Deploy** by hand: the footer then shows
`<branch>-<commit>` instead of a version. The `github-pages` environment only accepts `main`.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
