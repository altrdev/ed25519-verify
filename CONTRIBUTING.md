# Contributing

Thanks for your interest in Ed25519 signature tools! Bug reports, ideas and pull requests are welcome.

## Reporting a problem or suggesting something

Open an [issue](https://github.com/altrdev/ed25519-verify/issues). For a bug, the most useful things are:

- what you did and what you expected to happen;
- the encoding selected (hex / base64) and the message format;
- the browser and version.

You can include a public key, a message and a signature to reproduce a verification problem. **Never paste a private key
you care about** in an issue. If you think you found a security problem, please do not post the details publicly:
contact the maintainer through the email on their GitHub profile.

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
| `npm run build` | Type-check and production build in `dist/` |
| `npm run preview` | Serves the production build locally |

## Making a change

1. Create a branch from `main`.
2. Make the change, with tests (see below).
3. Run `npm run typecheck`, `npm test` and `npm run build`: all three must pass.
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

Every push to `main` is tested, built and published to GitHub Pages by
[`deploy-to-gh-pages.yml`](.github/workflows/deploy-to-gh-pages.yml).

Releases use [semantic versioning](https://semver.org/) and are published by
[`release.yml`](.github/workflows/release.yml) when a tag is pushed. To cut one (maintainers):

```bash
git checkout main && git pull
npm version minor          # or patch / major: bumps package.json and creates the tag vX.Y.Z
git push --follow-tags
```

The workflow refuses a tag that does not match the version in `package.json`, runs the tests and the build, and creates the GitHub
release with generated notes and the built site attached as a zip.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
