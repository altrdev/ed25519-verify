# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it privately through GitHub:
[Report a vulnerability](https://github.com/altrdev/ed25519-verify/security/advisories/new)
(the *Security* tab of the repository, then *Report a vulnerability*).

Include what you found, how to reproduce it (a public key, message and signature are fine; **never a private key you care
about**), the browser and the app version (shown in the page footer). You will get an answer as soon as possible; this is a
small project maintained by one person, so please be patient.

## What is in scope

The app is a static page that does everything in the browser. These matter most:

- **A wrong verdict**: a signature reported as valid when it is not under RFC 8032 (or the reverse), including how the
  permissive ZIP215 case is flagged.
- **Key and signature parsing**: a key or signature read as a different value than the text says (the app must refuse or ask,
  never guess), crashes or hangs on crafted input.
- **Anything that could send data out of the browser** or leak a private key: requests to other hosts, a private key ending up
  in a link, the clipboard or storage without the user asking, a weakened [Content-Security-Policy](src/csp.ts).
- **The build and release pipeline**: a way to publish something that is not the code of the repository.

Out of scope: problems of the browser, the operating system or a browser extension, and the keys you paste being handled
carelessly on your side (a generated key is only as safe as the computer that shows it).

## Supported versions

Only the latest release, which is also what the website serves. Fixes are published as a new release.

## What the project guarantees

- Everything runs in your browser; keys, messages and signatures are never sent anywhere.
- A strict Content-Security-Policy allows same-origin resources only, no inline or remote scripts.
- Signature verification uses [@noble/ed25519](https://github.com/paulmillr/noble-ed25519) with strict RFC 8032 rules.
- Share links carry public data only, in the part of the URL after `#`, which browsers never send to a server.
