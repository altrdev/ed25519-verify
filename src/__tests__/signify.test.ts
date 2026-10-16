import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '../bytes';
import {
    deriveKeyNumber,
    encodeSignify,
    encodeSignifyPublic,
    keyNumberText,
    looksLikeSignify,
    looksLikeSignifyPublic,
    parseKeyNumber,
    parseSignify,
    parseSignifyPublic,
    SignifyError,
    signSignify,
} from '../signify';
import { MS_SIG_HASHED } from './fixtures/minisign';
import { SG_KEY_NUMBER, SG_MESSAGE, SG_PUBLIC_FILE, SG_PUBLIC_HEX, SG_PUBLIC_LINE, SG_SEED, SG_SIG } from './fixtures/signify';

const message = new TextEncoder().encode(SG_MESSAGE);
const seed = hexToBytes(SG_SEED);
const error = (build: () => unknown) => {
    try {
        build();
    } catch (e) {
        return e instanceof SignifyError ? e.message : `other: ${e}`;
    }
    return 'no error';
};

describe('files made by signify', () => {
    it('reads the public key, as a file or as its line', () => {
        for (const text of [SG_PUBLIC_FILE, SG_PUBLIC_LINE, `${SG_PUBLIC_FILE}\n\n`, SG_PUBLIC_FILE.replace(/\n/g, '\r\n')]) {
            const parsed = parseSignifyPublic(text);
            expect(bytesToHex(parsed.publicKey)).toBe(SG_PUBLIC_HEX);
            expect(keyNumberText(parsed.keyNumber)).toBe(SG_KEY_NUMBER);
            expect(looksLikeSignifyPublic(text)).toBe(true);
        }
    });

    it('reads the signature and verifies it over the message itself', async () => {
        const parsed = parseSignify(SG_SIG);
        expect(keyNumberText(parsed.keyNumber)).toBe(SG_KEY_NUMBER);
        expect(parsed.untrustedComment).toBe('verify with signify.pub');
        expect(await ed.verifyAsync(parsed.signature, message, hexToBytes(SG_PUBLIC_HEX), { zip215: false })).toBe(true);
        expect(
            await ed.verifyAsync(parsed.signature, new TextEncoder().encode('hello world'), hexToBytes(SG_PUBLIC_HEX), { zip215: false }),
        ).toBe(false);
    });

    it('writes the same files back', () => {
        const parsed = parseSignify(SG_SIG);
        expect(encodeSignify({ keyNumber: parsed.keyNumber, signature: parsed.signature, untrustedComment: parsed.untrustedComment })).toBe(
            SG_SIG,
        );
        expect(encodeSignifyPublic(parseSignifyPublic(SG_PUBLIC_FILE))).toBe(SG_PUBLIC_FILE);
    });
});

describe('what is a signify signature and what is not', () => {
    it('is told from a minisign one, which has four lines and a trusted comment', () => {
        expect(looksLikeSignify(SG_SIG)).toBe(true);
        expect(looksLikeSignify(MS_SIG_HASHED)).toBe(false);
        expect(error(() => parseSignify(MS_SIG_HASHED))).toMatch(/minisign signature/);
    });

    it('is never a plain signature or another key', () => {
        for (const text of ['', SG_PUBLIC_HEX, SG_PUBLIC_LINE, 'untrusted comment: x', `untrusted comment: x\n${SG_PUBLIC_LINE}`]) {
            expect(looksLikeSignify(text)).toBe(false);
        }
        expect(looksLikeSignifyPublic(SG_PUBLIC_HEX)).toBe(false);
    });
});

describe('key numbers', () => {
    it('are the 8 bytes of the file in hex, and read back', () => {
        expect(bytesToHex(parseKeyNumber(SG_KEY_NUMBER))).toBe(SG_KEY_NUMBER);
        expect(error(() => parseKeyNumber('123'))).toMatch(/16 hexadecimal digits/);
        expect(error(() => parseKeyNumber('zzzzzzzzzzzzzzzz'))).toMatch(/16 hexadecimal digits/);
    });

    it('are derived from the key when it has none, always the same', () => {
        const key = hexToBytes(SG_PUBLIC_HEX);
        expect(bytesToHex(deriveKeyNumber(key))).toBe(bytesToHex(deriveKeyNumber(key)));
        expect(deriveKeyNumber(key)).toHaveLength(8);
    });
});

describe('signing', () => {
    it('with the key number of the key gives, byte for byte, the file signify wrote', async () => {
        const made = await signSignify(message, seed, { keyNumber: parseKeyNumber(SG_KEY_NUMBER) });
        expect(made.armored.split('\n')[1]).toBe(SG_SIG.split('\n')[1]);
        expect(made.publicFile).toBe(SG_PUBLIC_FILE);
    });
});

describe('malformed input', () => {
    it.each([
        ['nothing but a comment', 'untrusted comment: x', /two lines/],
        ['no base64', 'untrusted comment: x\n!!!', /not valid base64/],
        ['a short signature', `untrusted comment: x\n${SG_PUBLIC_LINE}`, /has 42 bytes, a signify one has 74/],
    ])('a signature with %s', (_, text, expected) => {
        expect(error(() => parseSignify(text))).toMatch(expected);
    });

    it('a key that is not 42 bytes, or has another algorithm', () => {
        expect(error(() => parseSignifyPublic(`untrusted comment: x\n${SG_SIG.split('\n')[1]}`))).toMatch(
            /has 74 bytes, it should have 42/,
        );
        const other = Buffer.from(SG_PUBLIC_LINE, 'base64');
        other[0] = 0x58;
        expect(error(() => parseSignifyPublic(other.toString('base64')))).toMatch(/algorithm is not "Ed"/);
    });

    it('a signature with another algorithm', () => {
        const body = Buffer.from(SG_SIG.split('\n')[1], 'base64');
        body[1] = 0x58;
        expect(error(() => parseSignify(`untrusted comment: x\n${body.toString('base64')}`))).toMatch(/expected "Ed"/);
    });
});

const signify = spawnSync('signify-openbsd', ['-V']).error ? null : 'signify-openbsd';
describe.skipIf(!signify)('with the real signify', () => {
    const dir = mkdtempSync(join(tmpdir(), 'signify-'));
    const run = (args: string[]) => spawnSync('signify-openbsd', args, { encoding: 'utf8' });

    it('accepts a signature made here, with the public key file made here', async () => {
        const made = await signSignify(message, seed);
        writeFileSync(join(dir, 'msg'), message);
        writeFileSync(join(dir, 'msg.sig'), made.armored);
        writeFileSync(join(dir, 'key.pub'), made.publicFile);
        const result = run(['-V', '-p', join(dir, 'key.pub'), '-m', join(dir, 'msg'), '-x', join(dir, 'msg.sig')]);
        expect(result.status, result.stderr + result.stdout).toBe(0);
    });

    it('refuses a signature made here when the message is changed, or the key is another', async () => {
        const made = await signSignify(message, seed);
        writeFileSync(join(dir, 'other'), 'hello world');
        writeFileSync(join(dir, 'other.sig'), made.armored);
        writeFileSync(join(dir, 'other.pub'), made.publicFile);
        expect(run(['-V', '-p', join(dir, 'other.pub'), '-m', join(dir, 'other'), '-x', join(dir, 'other.sig')]).status).not.toBe(0);
        const another = await signSignify(message, hexToBytes('11'.repeat(32)));
        writeFileSync(join(dir, 'another.pub'), another.publicFile);
        writeFileSync(join(dir, 'm'), message);
        expect(run(['-V', '-p', join(dir, 'another.pub'), '-m', join(dir, 'm'), '-x', join(dir, 'other.sig')]).status).not.toBe(0);
    });
});
