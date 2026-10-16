import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { hexToBytes } from '../bytes';
import {
    candidateKeys,
    crc24,
    type KeyReview,
    PgpError,
    type Packet,
    parseCertificate,
    parsePgpSignature,
    readPackets,
    readPgp,
    reviewCertificate,
    signedHash,
    spaced,
    standingOf,
} from '../openpgp';
import {
    PGP_BINARY_SIG_HEX,
    PGP_CERTIFIED_PUBLIC,
    PGP_CLEARSIGNED,
    PGP_DETACHED_PRIMARY,
    PGP_DETACHED_SUB,
    PGP_DETACHED_TEXT,
    PGP_EXPIRED_PRIMARY_FINGERPRINT,
    PGP_EXPIRED_PUBLIC,
    PGP_EXPIRED_SIG,
    PGP_EXPIRED_SUBKEY_FINGERPRINT,
    PGP_MESSAGE,
    PGP_PARTS_PRIMARY_FINGERPRINT,
    PGP_PARTS_REVOKED_PUBLIC,
    PGP_PARTS_REVOKED_SIG,
    PGP_PARTS_SUBKEY_FINGERPRINT,
    PGP_PRIMARY_FINGERPRINT,
    PGP_PUBLIC,
    PGP_REVOKED_PRIMARY_FINGERPRINT,
    PGP_REVOKED_PUBLIC,
    PGP_REVOKED_SIG,
    PGP_REVOKED_SUBKEY_FINGERPRINT,
    PGP_SUBKEY_FINGERPRINT,
    PGP_TEXT,
    PGP_V6_FINGERPRINT,
    PGP_V6_PUBLIC,
    PGP_V6_SIG,
} from './fixtures/openpgp';

const text = (s: string) => new TextEncoder().encode(s);
const armoredBytes = (armor: string) => {
    const read = readPgp(armor);
    if (!('armored' in read)) throw new Error('cleartext');
    return read.armored.bytes;
};
const failure = async (build: () => unknown) => {
    try {
        await build();
    } catch (e) {
        return e instanceof PgpError ? e.message : `other: ${e}`;
    }
    return 'no error';
};

/** Verifies a detached signature of GnuPG / Sequoia the way the page does: hash, then Ed25519 over the hash. */
async function check(signatureArmor: string, publicArmor: string, document: Uint8Array) {
    const signature = parsePgpSignature(armoredBytes(signatureArmor));
    const certificate = await parseCertificate(armoredBytes(publicArmor));
    const candidates = candidateKeys(signature, certificate.keys);
    const hash = await signedHash(signature, document);
    const results = await Promise.all(candidates.map((key) => ed.verifyAsync(signature.signature, hash, key.publicKey, { zip215: false })));
    return { signature, certificate, candidates, hash, valid: results.some(Boolean) };
}

describe('the armor', () => {
    it('has the CRC-24 of RFC 4880', () => {
        expect(crc24(new Uint8Array(0))).toBe(0xb704ce);
        // the checksum line of the armor made by gpg is the CRC-24 of the bytes it holds
        const lines = PGP_DETACHED_SUB.trim().split('\n');
        const checksum = lines.find((line) => /^=.{4}$/.test(line)) as string;
        const crc = crc24(armoredBytes(PGP_DETACHED_SUB));
        expect(Buffer.from(checksum.slice(1), 'base64').readUIntBE(0, 3)).toBe(crc);
    });

    it('refuses a text that was altered or cut', async () => {
        const firstBody = PGP_DETACHED_SUB.split('\n')[2];
        const corrupted = PGP_DETACHED_SUB.replace(
            firstBody,
            `${firstBody.slice(0, 5)}${firstBody[5] === 'A' ? 'B' : 'A'}${firstBody.slice(6)}`,
        );
        expect(await failure(() => readPgp(corrupted))).toMatch(/checksum of the armor does not match/);
        expect(await failure(() => readPgp(PGP_DETACHED_SUB.replace('-----END PGP SIGNATURE-----', '')))).toMatch(/cut short/);
        expect(await failure(() => readPgp('-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAAAA\n-----END PGP PRIVATE KEY BLOCK-----'))).toMatch(
            /PRIVATE key/,
        );
        expect(await failure(() => readPgp('nonsense !!'))).toMatch(/Expected an armored block/);
    });
});

describe('a key made by GnuPG', () => {
    it('is read with its primary key, its subkey, their fingerprints and key IDs, and its user ID', async () => {
        const certificate = await parseCertificate(armoredBytes(PGP_PUBLIC));
        expect(certificate.userIds).toEqual(['Fixture <fixture@example.com>']);
        expect(certificate.keys.map((key) => [key.fingerprint, key.primary, key.version, key.algorithm])).toEqual([
            [PGP_PRIMARY_FINGERPRINT, true, 4, 22],
            [PGP_SUBKEY_FINGERPRINT, false, 4, 22],
        ]);
        expect(certificate.keys[0].keyId).toBe(PGP_PRIMARY_FINGERPRINT.slice(-16));
        expect(spaced(PGP_PRIMARY_FINGERPRINT)).toBe('338D FA4E A322 CF87 3463 E8F3 8108 8537 2252 6153');
    });

    it('refuses a private key', async () => {
        const secret = Uint8Array.of(0xc5, 0x01, 0x00);
        expect(await failure(() => parseCertificate(secret))).toMatch(/PRIVATE key/);
    });
});

describe('signatures made by GnuPG', () => {
    it('a binary detached signature, made by the subkey: the key it names is found, and it verifies', async () => {
        const result = await check(PGP_DETACHED_SUB, PGP_PUBLIC, text(PGP_MESSAGE));
        expect(result.valid).toBe(true);
        expect(result.signature).toMatchObject({ version: 4, type: 0, algorithm: 22, hash: 10, issuerFingerprint: PGP_SUBKEY_FINGERPRINT });
        expect(result.candidates.map((key) => key.fingerprint)).toEqual([PGP_SUBKEY_FINGERPRINT]);
        // the two bytes of the hash that the signature keeps
        expect(Array.from(result.hash.slice(0, 2))).toEqual(Array.from(result.signature.hashPrefix));
        expect(result.signature.created).toBeGreaterThan(1.7e9);
    });

    it('made by the primary key', async () => {
        const result = await check(PGP_DETACHED_PRIMARY, PGP_PUBLIC, text(PGP_MESSAGE));
        expect(result.valid).toBe(true);
        expect(result.candidates[0].primary).toBe(true);
    });

    it('a binary .sig file (not armored)', async () => {
        const signature = parsePgpSignature(hexToBytes(PGP_BINARY_SIG_HEX));
        expect(signature.issuerFingerprint).toBe(PGP_SUBKEY_FINGERPRINT);
        const read = readPgp(PGP_BINARY_SIG_HEX);
        expect('armored' in read && read.armored.bytes.length).toBe(PGP_BINARY_SIG_HEX.length / 2);
    });

    it('is wrong for another message, and the hash prefix says the message is not the signed one', async () => {
        const result = await check(PGP_DETACHED_SUB, PGP_PUBLIC, text('hello world'));
        expect(result.valid).toBe(false);
        expect(Array.from(result.hash.slice(0, 2))).not.toEqual(Array.from(result.signature.hashPrefix));
    });

    it('is not valid for a key that did not make it, but the hash prefix still matches the message', async () => {
        const other = await check(PGP_DETACHED_SUB, PGP_V6_PUBLIC, text(PGP_MESSAGE));
        expect(other.candidates).toHaveLength(0); // the key it names is not in that block
        const signature = parsePgpSignature(armoredBytes(PGP_DETACHED_SUB));
        const certificate = await parseCertificate(armoredBytes(PGP_V6_PUBLIC));
        const hash = await signedHash(signature, text(PGP_MESSAGE));
        expect(await ed.verifyAsync(signature.signature, hash, certificate.keys[0].publicKey, { zip215: false })).toBe(false);
    });

    it('a text signature canonicalizes the line breaks (CR LF), so the same text with CR LF verifies too', async () => {
        const signature = parsePgpSignature(armoredBytes(PGP_DETACHED_TEXT));
        expect(signature.type).toBe(1);
        const certificate = await parseCertificate(armoredBytes(PGP_PUBLIC));
        const key = candidateKeys(signature, certificate.keys)[0];
        for (const variant of [PGP_TEXT, PGP_TEXT.replace(/\n/g, '\r\n')]) {
            expect(
                await ed.verifyAsync(signature.signature, await signedHash(signature, text(variant)), key.publicKey, { zip215: false }),
            ).toBe(true);
        }
        // trailing spaces are signed in a detached text signature: removing them changes it
        expect(
            await ed.verifyAsync(signature.signature, await signedHash(signature, text(PGP_TEXT.replace('one  ', 'one'))), key.publicKey, {
                zip215: false,
            }),
        ).toBe(false);
    });
});

describe('cleartext signed messages', () => {
    it('are read: the dash-escape is undone, the trailing spaces are not signed, and it verifies', async () => {
        const read = readPgp(PGP_CLEARSIGNED);
        if (!('cleartext' in read)) throw new Error('expected cleartext');
        expect(read.cleartext.text).toBe('line one\r\nline two\r\n- dashed line');
        expect(read.cleartext.hashes).toEqual(['SHA512']);
        const signature = parsePgpSignature(read.cleartext.signature);
        const certificate = await parseCertificate(armoredBytes(PGP_PUBLIC));
        const key = candidateKeys(signature, certificate.keys)[0];
        expect(
            await ed.verifyAsync(signature.signature, await signedHash(signature, text(read.cleartext.text)), key.publicKey, {
                zip215: false,
            }),
        ).toBe(true);
    });

    it('is refused when the text is changed', async () => {
        const read = readPgp(PGP_CLEARSIGNED.replace('line two', 'line 2'));
        if (!('cleartext' in read)) throw new Error('expected cleartext');
        const signature = parsePgpSignature(read.cleartext.signature);
        const certificate = await parseCertificate(armoredBytes(PGP_PUBLIC));
        const key = candidateKeys(signature, certificate.keys)[0];
        expect(
            await ed.verifyAsync(signature.signature, await signedHash(signature, text(read.cleartext.text)), key.publicKey, {
                zip215: false,
            }),
        ).toBe(false);
    });
});

describe('version 6 (RFC 9580) made by Sequoia', () => {
    it('the key has the fingerprint Sequoia computed (SHA-256 over a 0x9B packet), and the Ed25519 algorithm 27', async () => {
        const certificate = await parseCertificate(armoredBytes(PGP_V6_PUBLIC));
        expect(certificate.keys[0]).toMatchObject({ fingerprint: PGP_V6_FINGERPRINT, version: 6, algorithm: 27, primary: true });
        expect(certificate.keys[0].keyId).toBe(PGP_V6_FINGERPRINT.slice(0, 16));
        expect(certificate.userIds).toEqual(['Fixture V6 <v6@example.com>']);
    });

    it('a version 6 signature, with its salt, verifies', async () => {
        const result = await check(PGP_V6_SIG, PGP_V6_PUBLIC, text(PGP_MESSAGE));
        expect(result.signature).toMatchObject({ version: 6, algorithm: 27, hash: 10 });
        expect(result.signature.salt.length).toBeGreaterThan(0);
        expect(result.valid).toBe(true);
        expect((await check(PGP_V6_SIG, PGP_V6_PUBLIC, text('hello world'))).valid).toBe(false);
    });
});

describe('what is refused, and why', () => {
    it('a packet that is not a signature, other kinds of signature, a cut signature', async () => {
        expect(await failure(() => parsePgpSignature(armoredBytes(PGP_PUBLIC)))).toMatch(/public key, not a signature/);
        expect(await failure(() => parsePgpSignature(hexToBytes(PGP_BINARY_SIG_HEX.slice(0, 40))))).toMatch(/cut short/);
        const bytes = armoredBytes(PGP_DETACHED_SUB);
        const changed = (index: number, value: number) => {
            const copy = bytes.slice();
            copy[index] = value;
            return copy;
        };
        // header: c2 75 | 04 type algo hash …
        expect(await failure(() => parsePgpSignature(changed(3, 0x13)))).toMatch(/certification of a user ID, not for a document/);
        expect(await failure(() => parsePgpSignature(changed(4, 1)))).toMatch(/RSA/);
        expect(await failure(() => parsePgpSignature(changed(2, 3)))).toMatch(/version 3/);
        expect(await failure(() => parsePgpSignature(changed(2, 5)))).toMatch(/version 5/);
    });

    it('a hash that is broken or not computed here', async () => {
        const bytes = armoredBytes(PGP_DETACHED_SUB);
        const withHash = (hash: number) => {
            const copy = bytes.slice();
            copy[5] = hash;
            return parsePgpSignature(copy);
        };
        expect(await failure(() => signedHash(withHash(2), text('x')))).toMatch(/SHA-1, which is broken/);
        expect(await failure(() => signedHash(withHash(11), text('x')))).toMatch(/SHA-224, which this page cannot compute/);
    });

    it('packets with a wrong header or cut short', () => {
        expect(() => readPackets(Uint8Array.of(0x01))).toThrow(PgpError);
        expect(() => readPackets(Uint8Array.of(0xc2, 0x05, 0x00))).toThrow(/cut short/);
    });
});

// ---- what the key block says about a key -------------------------------------------------------------------------------------

/** The packets written back as new-format packets, to build a block that was altered. */
const assemble = (packets: Packet[]) => {
    const parts = packets.map(({ tag, body }) => {
        const header =
            body.length < 192
                ? [0xc0 | tag, body.length]
                : [0xc0 | tag, 0xff, body.length >>> 24, (body.length >> 16) & 255, (body.length >> 8) & 255, body.length & 255];
        return Uint8Array.of(...header, ...body);
    });
    return Uint8Array.from(parts.flatMap((part) => Array.from(part)));
};
const packetsOf = (armor: string) => readPackets(armoredBytes(armor));
const review = (armor: string) => reviewCertificate(armoredBytes(armor));
const keyOf = (r: Awaited<ReturnType<typeof review>>, fingerprint: string) =>
    r.keys.find((k) => k.key.fingerprint === fingerprint) as KeyReview;
const jan2020 = 1577880000;
const YEAR = 365 * 86400;
const at = (iso: string) => Date.parse(iso) / 1000;

describe('the self-signatures of a key block', () => {
    it('a key made by GnuPG: the primary key, the user ID and the subkey are bound by signatures that verify', async () => {
        const result = await review(PGP_PUBLIC);
        expect(result.keys.map((k) => [k.key.fingerprint, k.binding, k.expires, k.revocations.length])).toEqual([
            [PGP_PRIMARY_FINGERPRINT, 'checked', null, 0],
            [PGP_SUBKEY_FINGERPRINT, 'checked', null, 0],
        ]);
        expect(result.userIds).toMatchObject([{ userId: 'Fixture <fixture@example.com>', certification: 'checked', revocations: [] }]);
        expect(result.othersCertifications).toBe(0);
    });

    it('a version 6 key made by Sequoia (the user ID signature and the direct key signature hash a 0x9B key)', async () => {
        const result = await review(PGP_V6_PUBLIC);
        expect(result.keys.map((k) => [k.key.version, k.binding])).toEqual([
            [6, 'checked'],
            [6, 'checked'],
        ]);
        expect(result.userIds[0].certification).toBe('checked');
    });

    it('a user ID that was changed is no longer bound to the key: the signature over it does not verify', async () => {
        const packets = packetsOf(PGP_PUBLIC);
        const uid = packets.findIndex((p) => p.tag === 13);
        packets[uid] = { tag: 13, body: text('Mallory <fixture@example.com>') };
        const result = await reviewCertificate(assemble(packets));
        expect(result.userIds[0]).toMatchObject({ userId: 'Mallory <fixture@example.com>', certification: 'wrong' });
        expect(result.keys[0].binding).toBe('wrong'); // the key has no other signature over itself
        expect(result.keys[1].binding).toBe('checked'); // the subkey does not depend on the user ID
    });

    it('a user ID with no signature of the key is only claimed by the block', async () => {
        const packets = packetsOf(PGP_PUBLIC);
        const uid = packets.findIndex((p) => p.tag === 13);
        packets.splice(uid + 1, 1); // the signature that follows it
        const result = await reviewCertificate(assemble(packets));
        expect(result.userIds[0].certification).toBe('missing');
        expect(result.keys[0].binding).toBe('missing');
    });

    it('a subkey that was swapped is not bound to the primary key', async () => {
        const packets = packetsOf(PGP_PUBLIC);
        const sub = packets.findIndex((p) => p.tag === 14);
        const body = packets[sub].body.slice();
        body[4] ^= 1; // the creation time of the subkey
        packets[sub] = { tag: 14, body };
        const result = await reviewCertificate(assemble(packets));
        expect(result.keys[1].binding).toBe('wrong');
        expect(result.keys[0].binding).toBe('checked');
    });

    it('a subkey with no binding signature at all', async () => {
        const packets = packetsOf(PGP_PUBLIC);
        packets.pop(); // the binding of the subkey is the last packet
        expect((await reviewCertificate(assemble(packets))).keys[1].binding).toBe('missing');
    });

    it('counts the certifications of other keys without looking at them (the web of trust)', async () => {
        const result = await review(PGP_CERTIFIED_PUBLIC);
        expect(result.othersCertifications).toBe(1);
        expect(result.userIds[0].certification).toBe('checked'); // its own, not the other key's
    });
});

describe('the expiry of a key', () => {
    it('is the creation time plus the key expiration time of the newest signature that verifies', async () => {
        const result = await review(PGP_EXPIRED_PUBLIC);
        expect(keyOf(result, PGP_EXPIRED_PRIMARY_FINGERPRINT).expires).toBe(jan2020 + YEAR); // 1y at creation, 2020-12-31
        expect(keyOf(result, PGP_EXPIRED_SUBKEY_FINGERPRINT).expires).toBe(jan2020 + 180 * 86400); // 6m, 2020-06-29
    });

    it('a signature that does not verify says nothing: the expiry is not known', async () => {
        const packets = packetsOf(PGP_EXPIRED_PUBLIC);
        const uid = packets.findIndex((p) => p.tag === 13);
        packets[uid] = { tag: 13, body: text('Mallory') };
        const result = await reviewCertificate(assemble(packets));
        expect(result.keys[0].expires).toBeUndefined();
        expect(result.keys[1].expires).toBe(jan2020 + 180 * 86400);
    });
});

describe('revocations in the block', () => {
    it('a key revoked with gpg --gen-revoke: the reason and the date, checked', async () => {
        const result = await review(PGP_REVOKED_PUBLIC);
        expect(keyOf(result, PGP_REVOKED_PRIMARY_FINGERPRINT).revocations).toEqual([
            { created: at('2020-06-01T12:00:00Z'), code: 2, text: 'fixture compromised', check: 'checked' },
        ]);
        expect(keyOf(result, PGP_REVOKED_SUBKEY_FINGERPRINT).revocations).toEqual([]);
    });

    it('a user ID and a subkey revoked, the rest of the key not', async () => {
        const result = await review(PGP_PARTS_REVOKED_PUBLIC);
        expect(keyOf(result, PGP_PARTS_PRIMARY_FINGERPRINT).revocations).toEqual([]);
        expect(keyOf(result, PGP_PARTS_SUBKEY_FINGERPRINT).revocations).toMatchObject([
            { code: 3, text: 'this subkey is replaced', check: 'checked' },
        ]);
        expect(result.userIds.map((u) => [u.userId, u.revocations.map((r) => [r.code, r.check])])).toEqual([
            ['Kept Fixture <kept@example.com>', []],
            ['Dropped Fixture <dropped@example.com>', [[32, 'checked']]],
        ]);
        expect(result.userIds.every((u) => u.certification === 'checked')).toBe(true);
    });

    it('a revocation whose signature does not verify is kept apart and does not count', async () => {
        const packets = packetsOf(PGP_REVOKED_PUBLIC);
        const revocation = packets.findIndex((p) => p.tag === 2 && p.body[1] === 0x20);
        const body = packets[revocation].body.slice();
        body[body.length - 1] ^= 1; // the last byte of the signature
        packets[revocation] = { tag: 2, body };
        const result = await reviewCertificate(assemble(packets));
        expect(keyOf(result, PGP_REVOKED_PRIMARY_FINGERPRINT).revocations).toMatchObject([{ code: 2, check: 'wrong' }]);
        const now = at('2026-10-17T00:00:00Z');
        const standing = standingOf(
            result,
            keyOf(result, PGP_REVOKED_SUBKEY_FINGERPRINT).key,
            parsePgpSignature(armoredBytes(PGP_REVOKED_SIG)),
            now,
        );
        expect(standing.issues).toEqual([]);
        expect(standing.facts.join(' ')).toMatch(/revocation signature that does not verify; it is ignored/);
    });
});

describe('what is said about a signature', () => {
    const now = at('2026-10-17T00:00:00Z');
    const stand = async (
        publicArmor: string,
        signatureArmor: string,
        change: Partial<ReturnType<typeof parsePgpSignature>> = {},
        when = now,
    ) => {
        const signature = { ...parsePgpSignature(armoredBytes(signatureArmor)), ...change };
        const certificate = await parseCertificate(armoredBytes(publicArmor));
        const key = candidateKeys(signature, certificate.keys)[0];
        return standingOf(await review(publicArmor), key, signature, when);
    };

    it('a key that has expired: the signature was made before it did, or after', async () => {
        const before = await stand(PGP_EXPIRED_PUBLIC, PGP_EXPIRED_SIG);
        expect(before.issues).toEqual([
            'The subkey expired on 2020-06-29. The signature was made before that, on 2020-03-01.',
            'The primary key expired on 2020-12-31. The signature was made before that, on 2020-03-01.',
        ]);
        const after = await stand(PGP_EXPIRED_PUBLIC, PGP_EXPIRED_SIG, { created: at('2020-08-01T00:00:00Z') });
        expect(after.issues[0]).toBe('The subkey expired on 2020-06-29. The signature was made AFTER that, on 2020-08-01.');
        expect(after.issues[1]).toMatch(/primary key expired on 2020-12-31. The signature was made before that/);
        const none = await stand(PGP_EXPIRED_PUBLIC, PGP_EXPIRED_SIG, { created: undefined });
        expect(none.issues[0]).toMatch(/carries no time/);
    });

    it('a key that has not expired yet says when it will', async () => {
        const standing = await stand(PGP_EXPIRED_PUBLIC, PGP_EXPIRED_SIG, {}, at('2020-04-01T00:00:00Z'));
        expect(standing.issues).toEqual([]);
        expect(standing.facts).toContain('The subkey expires on 2020-06-29.');
        expect(standing.facts).toContain('The primary key expires on 2020-12-31.');
    });

    it('a key revoked as compromised voids its signatures whatever their date', async () => {
        const standing = await stand(PGP_REVOKED_PUBLIC, PGP_REVOKED_SIG);
        expect(standing.issues).toEqual([
            'The primary key was revoked on 2020-06-01 (the key was compromised: "fixture compromised"): its signatures are not to be relied on, whatever their date.',
        ]);
    });

    it('a subkey revoked as retired only matters for the signatures made after it', async () => {
        const before = await stand(PGP_PARTS_REVOKED_PUBLIC, PGP_PARTS_REVOKED_SIG);
        expect(before.issues).toEqual([
            'The subkey was revoked on 2020-06-01 (the key is retired and no longer used: "this subkey is replaced"). The signature was made before the revocation.',
        ]);
        const after = await stand(PGP_PARTS_REVOKED_PUBLIC, PGP_PARTS_REVOKED_SIG, { created: at('2020-09-01T00:00:00Z') });
        expect(after.issues[0]).toMatch(/The signature was made AFTER the revocation\.$/);
    });

    it('a signature that has expired itself', async () => {
        const standing = await stand(PGP_PUBLIC, PGP_DETACHED_SUB, { created: at('2020-03-01T00:00:00Z'), expires: 86400 });
        expect(standing.issues).toEqual(['The signature itself expired on 2020-03-02.']);
    });

    it('nothing is wrong with a key that does not expire and has no revocation, and "not in this block" is not "not revoked"', async () => {
        const standing = await stand(PGP_PUBLIC, PGP_DETACHED_SUB);
        expect(standing.issues).toEqual([]);
        expect(standing.facts).toContain('No revocation of the subkey is in this block (it may exist elsewhere, e.g. on a keyserver).');
    });

    it('a subkey with no binding to the primary key is an issue, a user ID that is not signed is a fact of the block', async () => {
        const packets = packetsOf(PGP_PUBLIC);
        packets.pop();
        const altered = assemble(packets);
        const signature = parsePgpSignature(armoredBytes(PGP_DETACHED_SUB));
        const certificate = await parseCertificate(altered);
        const key = candidateKeys(signature, certificate.keys)[0];
        const standing = standingOf(await reviewCertificate(altered), key, signature, now);
        expect(standing.issues[0]).toMatch(/the block has no binding signature for this subkey/);
    });

    it('never says a key is trusted or valid: it says what was found in the block', async () => {
        for (const [pub, sig] of [
            [PGP_PUBLIC, PGP_DETACHED_SUB],
            [PGP_EXPIRED_PUBLIC, PGP_EXPIRED_SIG],
            [PGP_REVOKED_PUBLIC, PGP_REVOKED_SIG],
            [PGP_PARTS_REVOKED_PUBLIC, PGP_PARTS_REVOKED_SIG],
        ]) {
            const standing = await stand(pub, sig);
            expect([...standing.issues, ...standing.facts].join('\n')).not.toMatch(/\b(trust|trusted|valid)\b/i);
        }
    });
});

const gpg = spawnSync('gpg', ['--version']).error ? null : 'gpg';
describe.skipIf(!gpg)('with the real GnuPG', () => {
    it('the fixtures are accepted by gpg --verify with the key', () => {
        const dir = mkdtempSync(join(tmpdir(), 'pgp-'));
        const home = join(dir, 'home');
        const run = (args: string[]) => spawnSync('gpg', ['--homedir', home, '--batch', ...args], { encoding: 'utf8' });
        spawnSync('mkdir', ['-m', '700', home]);
        writeFileSync(join(dir, 'pub.asc'), PGP_PUBLIC);
        writeFileSync(join(dir, 'msg'), PGP_MESSAGE);
        writeFileSync(join(dir, 'sig.asc'), PGP_DETACHED_SUB);
        writeFileSync(join(dir, 'clear.asc'), PGP_CLEARSIGNED);
        expect(run(['--import', join(dir, 'pub.asc')]).status).toBe(0);
        const good = run(['--verify', join(dir, 'sig.asc'), join(dir, 'msg')]);
        expect(good.status, good.stderr).toBe(0);
        expect(good.stderr).toContain(PGP_SUBKEY_FINGERPRINT);
        writeFileSync(join(dir, 'other'), 'hello world');
        expect(run(['--verify', join(dir, 'sig.asc'), join(dir, 'other')]).status).not.toBe(0);
        expect(run(['--verify', join(dir, 'clear.asc')]).status).toBe(0);
        expect(PGP_PRIMARY_FINGERPRINT).toHaveLength(40);
    });
});

describe.skipIf(!gpg)('the key block read against the real GnuPG', () => {
    const run = (home: string, args: string[], input?: Buffer | string) =>
        spawnSync('gpg', ['--homedir', home, '--batch', '--with-colons', '--fixed-list-mode', ...args], { encoding: 'utf8', input });
    const home = () => {
        const dir = mkdtempSync(join(tmpdir(), 'pgp-review-'));
        const path = join(dir, 'home');
        spawnSync('mkdir', ['-m', '700', path]);
        return { dir, path };
    };
    type Line = string[];
    const listing = (path: string): Line[] =>
        run(path, ['--list-keys'])
            .stdout.split('\n')
            .filter(Boolean)
            .map((line) => line.split(':'));

    it('agrees on the expiry and the revocation of each key and user ID, and finds the self-signatures good', async () => {
        const now = Date.now() / 1000;
        for (const armor of [PGP_PUBLIC, PGP_EXPIRED_PUBLIC, PGP_REVOKED_PUBLIC, PGP_PARTS_REVOKED_PUBLIC, PGP_CERTIFIED_PUBLIC]) {
            const { dir, path } = home();
            writeFileSync(join(dir, 'pub.asc'), armor);
            expect(run(path, ['--import', join(dir, 'pub.asc')]).status).toBe(0);
            const mine = await review(armor);
            const gpgKeys = listing(path).filter((line) => line[0] === 'pub' || line[0] === 'sub');
            expect(gpgKeys).toHaveLength(mine.keys.length);
            mine.keys.forEach((k, i) => {
                const [, validity, , , , , expires] = gpgKeys[i];
                // the expiry date is the one gpg prints; expired keys are listed as "e" and revoked ones as "r"
                expect(expires ? Number(expires) : null, `expiry of ${k.key.fingerprint}`).toBe(k.expires ?? null);
                const revoked = k.revocations.some((r) => r.check === 'checked');
                // gpg lists the subkeys of a revoked primary key as revoked too
                const primaryRevoked = mine.keys[0].revocations.some((r) => r.check === 'checked');
                expect(validity === 'r', `revoked ${k.key.fingerprint}`).toBe(revoked || primaryRevoked);
                if (!revoked)
                    expect(validity === 'e', `expired ${k.key.fingerprint}`).toBe(typeof k.expires === 'number' && k.expires <= now);
            });
            const users = listing(path).filter((line) => line[0] === 'uid');
            mine.userIds.forEach((u, i) => {
                const line = users.find((candidate) => candidate[9] === u.userId);
                expect(line, u.userId).toBeDefined();
                const primaryRevoked = mine.keys[0].revocations.some((r) => r.check === 'checked');
                expect((line as Line)[1] === 'r', `user ID revoked ${u.userId}`).toBe(
                    primaryRevoked || u.revocations.some((r) => r.check === 'checked'),
                );
                expect(u.certification, `${i}`).toBe('checked');
            });
            // every self-signature gpg checks is good, none bad
            const all = run(path, ['--check-sigs']).stdout;
            // "?" is the certification by another key, which is not in this keyring: gpg cannot check it either
            expect(all).not.toMatch(/^(sig|rev):[-%]/m);
            expect(all).toMatch(/^sig:!/m);
        }
    });

    it('also refuses a user ID that was changed (the other direction): no valid user ID is left, and the review says wrong', async () => {
        const packets = packetsOf(PGP_PUBLIC);
        packets[packets.findIndex((p) => p.tag === 13)] = { tag: 13, body: text('Mallory <fixture@example.com>') };
        const altered = assemble(packets);
        const { path } = home();
        const result = run(path, ['--import'], Buffer.from(altered));
        expect(result.stderr + result.stdout).toMatch(/bad signature|no user ID|w\/o user IDs|no valid user IDs/);
        expect(listing(path).filter((line) => line[0] === 'pub')).toHaveLength(0);
        expect((await reviewCertificate(altered)).userIds[0].certification).toBe('wrong');
    });
});
