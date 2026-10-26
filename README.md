# Ed25519 signature tools

[![Build and Deploy](https://github.com/altrdev/ed25519-verify/actions/workflows/deploy-to-gh-pages.yml/badge.svg)](https://github.com/altrdev/ed25519-verify/actions/workflows/deploy-to-gh-pages.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Verify and create [Ed25519](https://ed25519.cr.yp.to/) signatures straight from your browser.
Paste a public key, a message and a signature to check them, or sign a message with a private key.
Everything runs client-side: **nothing is uploaded anywhere**.

**Live demo: <https://ed25519.altr.dev/>**

<p align="center">
  <img src="docs/screenshot-light.png" alt="Verifying a raw signature, light theme" width="49%">
  <img src="docs/screenshot-dark.png" alt="Verifying a JWT, dark theme" width="49%">
</p>

## Features

- **Verify** a signature given a public key and a message, with a clear valid / wrong result.
- **Sign** a message with a private key; the public key is deduced and shown next to it.
- **Generate** a random key pair with one click, handy for trying things out.
- **Clear input errors**: a malformed key or signature is explained next to the field ("expected 32 bytes, got 31",
  "not in a recognised format") instead of being reported as a wrong signature.
- Messages as **text, hex or base64**, so binary payloads can be signed and verified as well, or **a file** (*Choose file* or drag and drop, up to 100 MB): its bytes are read in the browser only and nothing is uploaded. A share link cannot carry a file.
- Keys in **PEM, OpenSSH or JWK** pasted as they are (detected automatically), or as plain hex / base64.
- **A rail of formats, one pattern**: *Raw signature* (a public key, a message and the 64 bytes) and, under *Containers*, one entry for each format below. In each, a switch chooses *Verify a signature* or *Create a signature*, the fields are listed one per row and the verdict card sits under the form: the verdict, the steps that were checked (key and signature sizes, points on the curve, S reduced, the equation) and what was read from the input.
- **Containers** (the rail): signatures in the formats other tools use. **JWS / JWT** (`alg: EdDSA`, RFC 7515 / 8037): paste a token and the public key (hex, PEM, OpenSSH or a JWK) to verify it and see its header, payload and times (a token can be correctly signed and expired); or create one from a private key, a header and a payload, which are signed exactly as written. It refuses an unsigned token (`alg: none`), another algorithm and a header with `crit`, and never trusts a key carried by the token. The public key can also be a whole **JWK Set** (`jwks.json`): the key the token names with `kid` is picked from it and the page says which one; no such key, two with the same `kid`, or a token with no `kid` and several keys, are explained or left to your choice, never guessed. It has the same help as the other views: *Copy link* (the token and the public key, in the part of the URL no server sees; opening it shows the answer), *Load example* (the token of RFC 8037, and an expired JWT), hints when the signature is wrong (the halves swapped, a private key in the public key field), and a token can be opened from a file. **SSH signatures** (`ssh-keygen -Y sign`, also what git uses with `gpg.format=ssh`): paste the signature, the message (typed or a file) and the public key you trust; the namespace, the hash and the key fingerprint inside the signature are shown, a signature made for another namespace or by another key is refused with the reason (never "wrong"), and without a trusted key it says for which key it is valid instead of calling it valid. It can also create them, in any namespace, with SHA-256 or SHA-512. Checked against OpenSSH in both directions. The key can be a whole **`allowed_signers`** or `authorized_keys` text: the entry that made the signature is found by its key (the signature carries it), its `namespaces=` option is applied, `cert-authority` entries and other key types are left out, and the options the page does not check (`valid-before`, `from`…) are listed, never silently ignored. **minisign** (`.minisig` and the `RW…` public key): verifies both forms (the usual one, which signs the BLAKE2b-512 hash of the message, and the legacy one), checks that the key is the one that made the signature (its key ID), and tells the *trusted comment* (signed) from the *untrusted comment* (anyone can change it): a signature whose trusted comment was altered is refused. It can create them too, with the `.pub` file to verify them. Checked against minisign in both directions. **signify** (OpenBSD, `.sig` and the `RW…` public key): the two-line little brother of minisign, which signs the message itself, with no hash and no trusted comment; it checks the key number against the key you gave, can create signatures with the `.pub` file, and tells a minisign signature (four lines) apart and points to its format. Checked against signify in both directions. **COSE** (`COSE_Sign1` and `COSE_Sign`, RFC 9052, EdDSA): paste the message as hex or base64 (or open the `.cose` file), the public key (any format, or a COSE_Key) and, if it travels apart, the payload and the external data; the signed header is shown apart from the unsigned one. A **CWT** (RFC 8392, also inside the tag 61) shows its claims by name, the times as dates, and whether the token is expired or not valid yet, kept apart from the verdict: *what the token says* is not *what the signature proves* (a token can be correctly signed and expired). A **COSE_Sign** (several signatures) is verified signature by signature: give a COSE_KeySet, or one key per line (COSE_Keys, or plain public keys); a signature is checked with the key that has its `kid`, and one with no key, or that this page cannot check, is listed as *not checked* with the reason; the message is called valid only when every signature was checked and is valid, never when some were not. It refuses other algorithms and critical parameters (on a COSE_Sign1; a signature of a COSE_Sign with one is left unchecked), and an algorithm that is not in the signed header. It can create them too, with the key ID, the content type, the payload inside or apart, and a binary download. Checked against the example of the COSE working group and against pycose (COSE_Sign1, CWT and COSE_Sign), byte for byte. **OpenPGP** (verification only): a detached signature (armored or the binary `.sig`), or a whole cleartext signed message, against a public key block (`gpg --armor --export`, with its subkeys and fingerprints) or a plain Ed25519 key; versions 4 and 6 (RFC 9580). Given a key block it also looks inside it, and says what it found: whether each user ID and subkey is bound to the primary key by a signature that verifies, when the keys expire (and whether the signature was made before or after), and the revocations the block holds (key, subkey, user ID, with the reason). It never calls a key "trusted": the web of trust and the keyservers are out of reach of a page that makes no requests, and "no revocation in this block" is not "not revoked". It finds the key that made the signature in the block, shows the fingerprint, the time and the hash, and says whether the message is the one that was signed (the two bytes of the hash that every signature keeps). It checks the mathematics only, not certification, expiry or revocation, and says so. It refuses private keys, RSA / ECDSA / Ed448 and SHA-1. Checked against GnuPG and Sequoia.
- **Containers are recognised when pasted** in the signature field of *Raw signature*: a JWT, an SSH signature, a minisign, signify or OpenPGP signature, a COSE message. A line under the field says what it is and *Open in* the format moves it to the view that reads it, with the public key and the message (or file) already typed. A plain signature, in any notation, is never taken for one.
- **Keys as files**: *Choose file* (or drop a file on the field) reads `id_ed25519`, `.pub`, `.pem`, `.jwk` or a Solana `keypair.json` into a key field, or a raw 32 / 64 byte binary key or 64 byte binary signature as hex; *Download* saves a key in the format it is shown in under the usual name (`id_ed25519`, `id_ed25519.pub`, `private.pem`, `public.pem`, `private.jwk`...). Files are read and written in the browser only; a private key is saved only when you click, with a reminder that the file is not encrypted.
- **Load example**: a button on each form fills the form with the test vectors of [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) (and, on the Verify tab, a signature that only the permissive ZIP215 rules accept, to see the warning). On the Sign tab it loads a vector's private key and tells you when the signature you get is the published one.
- **Hints when a signature is wrong**: Ed25519 cannot say which input is at fault, so when verification fails the app retries it with the usual mistakes undone (a newline added or missing, line breaks `\r\n`, the message read as hex or base64 by mistake, a hash signed instead of the message, a private key pasted as the public key, the two halves of the signature swapped) and tells you which one makes it valid. It also states what is certain: a signature whose S is not reduced, or a point that is not on the curve. A signature that is simply wrong gets no hint.
- **Share a verification**: *Copy link* on the verification of a raw signature makes a link with the public key, message and signature in the part after `#`, which browsers never send to any server. Whoever opens it sees the fields filled in and the result at once. Private keys are never put in a link.
- **Formats are recognised by themselves** for keys and signatures: hex, `0x` hex, base64, base64url, base58, base32 or a list of bytes, mixed as you like. When a text could be two things (rare) you are asked to pick, never guessed for. A menu on every field converts it to another format.
- Private key hidden by default, one-click **copy** for private and public keys and for signatures.
- **The verdict is easy to find**: a click on *Verify* (or *Load example*) scrolls to the verdict card when it is out of view, and a pill beside the button gives the verdict in a word (*Valid*, *Wrong*, *ZIP215 only*...).
- **A help dialog** (the *?* in the top bar): what the page does, how to read *valid* and *wrong*, which view reads which file, and what the ZIP215 warning means. It closes with Escape, the close button or a click outside.
- Light and dark theme, responsive layout, installable as a **PWA** (assets are precached by a service worker).

## Input formats

| Field | Format |
| --- | --- |
| Message | Plain text (signed as UTF-8 bytes), or raw bytes written in hex or base64. Empty messages are allowed |
| Public key | 32 bytes written as hex, `0x` hex, base64 (also URL-safe), base58, base32 or a list of numbers, or a key pasted as it is in a standard format: PEM (`BEGIN PUBLIC KEY`), OpenSSH (`ssh-ed25519 AAAA…`), JWK, `did:key`, a bare multibase key (`z6Mk…`, the `publicKeyMultibase` of a DID document), a DID document with one Ed25519 key, an `authorized_keys` / `allowed_signers` line, a Stellar `G…` address, a Tor v3 `.onion` address or a NEAR `ed25519:…` key |
| Private key | The 32-byte seed in any of the above notations (the 64-byte form, seed followed by public key, is accepted too, e.g. a Solana keypair file: the seed is used), or PEM PKCS#8 (`BEGIN PRIVATE KEY`), an unencrypted OpenSSH private key (`BEGIN OPENSSH PRIVATE KEY`) or a JWK, a Stellar `S…` seed or a NEAR `ed25519:…` secret key |
| Signature | 64 bytes in any of the notations above |

The notations: hex (`00ff10`), `0x`-prefixed hex, base64 and base64url (padding optional, wrapped lines fine), base58 (the
Bitcoin alphabet, as Solana, NEAR or IPFS write keys and signatures), base32 (RFC 4648) and a list of numbers such as
`[12, 34, 56]` (a Solana keypair file, or what Rust, Go and JavaScript print).

**Keys in other formats are recognised by themselves** as well: paste the content of the file and a
"Detected format" note appears under the field. A public key field also accepts a private JWK or OpenSSH private key (it
contains the public part). Keys of another type (RSA, EC, X25519, Ed448...) and keys protected by a passphrase are refused with
a message that says so; to use an encrypted key, remove the passphrase first (`ssh-keygen -p -f key`, or
`openssl pkey -in key.pem -out plain.pem`).

Signatures are checked with the strict rules of RFC 8032 / FIPS 186-5 (not the more permissive ZIP215 rules), so
"valid" means that a standards-compliant verifier agrees. In the rare case of a signature that fails the strict check
but would be accepted under ZIP215 (used by some consensus systems, e.g. Zcash), the result says so instead of just "wrong".

**No format to select for keys and signatures**: the app works it out. A key or a signature has only a few possible sizes
(a 32-byte key is 64 hex characters, 43 or 44 in base64, 43 or 44 in base58; a 64-byte signature is 128, 86 or 88, 87 or 88),
and in nearly every case only one reading of the text has such a size. A text made of hex digits only is always hex, so a
truncated hex key gets "expected 32 bytes, got 21" instead of being mistaken for something else.

**When a text could be two things**, the app does not guess. About 1 in 16 base58 keys has 43 characters, and 43 characters
are also a valid unpadded base64 key (a different one). It then says so and offers *Read as base64* and *Read as base58*:
one click settles it. The choice is dropped as soon as you edit the text.

**Every key and signature field has a format menu** (the small button next to *Copy*). It shows what the text was
recognised as, and picking another format **rewrites the field in that format**: the same bytes, written another way, so the
app doubles as a converter (a PEM public key to hex, a base58 signature to base64, a keypair file to a seed...). In the
fields that are results (the signature, a generated or deduced key) the menu chooses how they are written. The choice is
remembered for each field. Key fields also have a **Key files** group: PEM (PKCS#8 / SPKI), OpenSSH and JWK, so a hex seed can be exported as a `.pem`, an `id_ed25519` file or a JWK (and *Generate* writes a new pair that way). An **Ecosystems** group adds `did:key`, multibase (`z6Mk…`), Stellar (`G…` / `S…`), Tor v3 `.onion` addresses, NEAR (`ed25519:…`) and the Solana keypair file; they are recognised when pasted too, and their checksums (Stellar CRC16, onion SHA3) are verified, so a mistyped character is reported instead of giving another key. The message has its own Text / Hex / Base64 selector (a text cannot tell "abcd" the string
from "abcd" the two bytes), so you can sign and verify binary data (hashes, already encoded payloads) too.

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
  App.tsx           page shell: top bar, rail of formats, footer, theme toggle
  Help.tsx          the help dialog
  FormRaw.tsx       the raw signature view: the switch between verifying and creating
  FormVerify.tsx    verify a raw signature
  FormSign.tsx      create a raw signature
  Results.tsx       the verdict card under a form (Banner, Checks)
  Verdict.tsx       the verdict of a form: the pill beside Verify, the scroll to the card
  Checks.tsx        the steps of a verification, as a list
  __tests__/        tests
```

### Deployment

The site is published on GitHub Pages **by each release**, not by each push to `main`: the footer shows the version and the
release notes of what is online. Maintainers start a release from **Actions → Release → Run workflow**, see
[CONTRIBUTING.md](CONTRIBUTING.md#deployment-and-releases). In the repository settings, **Pages → Source** must be set to
**GitHub Actions**.

## Contributing

Issues and pull requests are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). Tagged versions are listed under
[Releases](https://github.com/altrdev/ed25519-verify/releases).
To report a security problem privately, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Alessandro Travi
