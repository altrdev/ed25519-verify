import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { hexToBytes } from '../bytes';
import { candidateKeys, crc24, PgpError, parseCertificate, parsePgpSignature, readPackets, readPgp, signedHash, spaced } from '../openpgp';
import {
    PGP_BINARY_SIG_HEX,
    PGP_CLEARSIGNED,
    PGP_DETACHED_PRIMARY,
    PGP_DETACHED_SUB,
    PGP_DETACHED_TEXT,
    PGP_MESSAGE,
    PGP_PRIMARY_FINGERPRINT,
    PGP_PUBLIC,
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
