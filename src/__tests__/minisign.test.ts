import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '../bytes';
import {
    checkTrustedComment,
    commentSignedBytes,
    deriveKeyId,
    encodeMinisign,
    keyIdText,
    looksLikeMinisignPublic,
    MinisignError,
    parseKeyId,
    parseMinisign,
    parseMinisignPublic,
    signedBytes,
    signMinisign,
} from '../minisign';
import {
    MS_KEY_ID,
    MS_MESSAGE,
    MS_PUBLIC_FILE,
    MS_PUBLIC_HEX,
    MS_PUBLIC_LINE,
    MS_SEED,
    MS_SIG_HASHED,
    MS_SIG_LEGACY,
    MS_TRUSTED_COMMENT,
} from './fixtures/minisign';

const message = new TextEncoder().encode(MS_MESSAGE);
const seed = hexToBytes(MS_SEED);
const publicKey = hexToBytes(MS_PUBLIC_HEX);
const error = (build: () => unknown) => {
    try {
        build();
    } catch (e) {
        return e instanceof MinisignError ? e.message : `other: ${e}`;
    }
    return 'no error';
};
const strict = { zip215: false };

describe('files made by minisign', () => {
    it('reads the public key, as a file or as its line', () => {
        for (const text of [MS_PUBLIC_FILE, MS_PUBLIC_LINE, `${MS_PUBLIC_FILE}\n\n`, MS_PUBLIC_FILE.replace(/\n/g, '\r\n')]) {
            const parsed = parseMinisignPublic(text);
            expect(bytesToHex(parsed.publicKey)).toBe(MS_PUBLIC_HEX);
            expect(keyIdText(parsed.keyId)).toBe(MS_KEY_ID);
            expect(looksLikeMinisignPublic(text)).toBe(true);
        }
    });

    it('does not take other keys for a minisign key', () => {
        for (const other of [MS_PUBLIC_HEX, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAyj+hwReHmoTLUCU/tIuzHePLxf/02FWL/L7jy/874Z', 'RWQ']) {
            expect(looksLikeMinisignPublic(other)).toBe(false);
        }
    });

    it('reads the hashed signature and verifies it over the BLAKE2b hash', async () => {
        const parsed = parseMinisign(MS_SIG_HASHED);
        expect(parsed).toMatchObject({
            algorithm: 'ED',
            trustedComment: MS_TRUSTED_COMMENT,
            untrustedComment: 'signature from minisign secret key',
        });
        expect(keyIdText(parsed.keyId)).toBe(MS_KEY_ID);
        expect(await ed.verifyAsync(parsed.signature, signedBytes('ED', message), publicKey, strict)).toBe(true);
        expect(await ed.verifyAsync(parsed.signature, message, publicKey, strict)).toBe(false);
        expect(
            await ed.verifyAsync(parsed.globalSignature, commentSignedBytes(parsed.signature, parsed.trustedComment), publicKey, strict),
        ).toBe(true);
    });

    it('reads the legacy signature, made over the message itself', async () => {
        const parsed = parseMinisign(MS_SIG_LEGACY);
        expect(parsed.algorithm).toBe('Ed');
        expect(await ed.verifyAsync(parsed.signature, signedBytes('Ed', message), publicKey, strict)).toBe(true);
        expect(await ed.verifyAsync(parsed.globalSignature, commentSignedBytes(parsed.signature, 'legacy one'), publicKey, strict)).toBe(
            true,
        );
    });

    it('does not accept an altered trusted comment', async () => {
        const parsed = parseMinisign(MS_SIG_HASHED.replace('1700000000', '1700000001'));
        expect(
            await ed.verifyAsync(parsed.globalSignature, commentSignedBytes(parsed.signature, parsed.trustedComment), publicKey, strict),
        ).toBe(false);
    });

    it('writes the same files back', () => {
        const parsed = parseMinisign(MS_SIG_HASHED);
        expect(encodeMinisign(parsed)).toBe(MS_SIG_HASHED);
    });
});

describe('signing', () => {
    it('with the key id of the key gives, byte for byte, the file minisign wrote', async () => {
        const made = await signMinisign(message, seed, { trustedComment: MS_TRUSTED_COMMENT, keyId: parseKeyId(MS_KEY_ID) });
        expect(made.armored).toBe(MS_SIG_HASHED);
        expect(made.publicFile).toBe(MS_PUBLIC_FILE);
    });

    it('without a key id derives always the same one from the key', async () => {
        const first = await signMinisign(message, seed, { trustedComment: '' });
        const second = await signMinisign(new Uint8Array(3), seed, { trustedComment: 'x' });
        expect(bytesToHex(first.keyId)).toBe(bytesToHex(deriveKeyId(publicKey)));
        expect(bytesToHex(second.keyId)).toBe(bytesToHex(first.keyId));
        expect(first.publicFile).toContain(`minisign public key ${keyIdText(first.keyId)}`);
    });

    it('refuses a trusted comment of several lines', async () => {
        expect(error(() => checkTrustedComment('a\nb'))).toMatch(/one line/);
        await expect(signMinisign(message, seed, { trustedComment: 'a\r\nb' })).rejects.toThrow(MinisignError);
    });
});

describe('key ids', () => {
    it('are written as minisign writes them (the bytes of the file reversed)', () => {
        expect(bytesToHex(parseKeyId(MS_KEY_ID))).toBe('c910f402c26049b7');
        expect(keyIdText(parseKeyId('0123456789abcdef'))).toBe('0123456789ABCDEF');
        expect(error(() => parseKeyId('xyz'))).toMatch(/16 hex/);
    });
});

describe('malformed input', () => {
    it.each([
        ['empty', '', /four lines/],
        ['three lines', MS_SIG_HASHED.split('\n').slice(0, 3).join('\n'), /four lines/],
        ['no comment label', MS_SIG_HASHED.replace('untrusted comment:', 'comment:'), /four lines/],
        ['no trusted label', MS_SIG_HASHED.replace('trusted comment:', 'comment:'), /four lines/],
        ['bad base64', MS_SIG_HASHED.replace(/\n(RU[^\n]*)\n/, '\n!!!\n'), /not valid base64/],
        ['short signature', MS_SIG_HASHED.replace(/\n(RU[^\n]*)\n/, '\nRUTJEPQCwmBJ\n'), /has 9 bytes/],
        ['global signature short', MS_SIG_HASHED.replace(/\n[^\n]+\n$/, '\nAAAA\n'), /3 bytes/],
    ])('a signature: %s', (_name, text, expected) => {
        expect(error(() => parseMinisign(text))).toMatch(expected);
    });

    it('a signature with another algorithm', () => {
        const body = Buffer.from(MS_SIG_HASHED.split('\n')[1], 'base64');
        body[0] = 0x41;
        const text = MS_SIG_HASHED.replace(MS_SIG_HASHED.split('\n')[1], body.toString('base64'));
        expect(error(() => parseMinisign(text))).toMatch(/not known/);
    });

    it.each([
        ['empty', ''],
        ['two key lines', `${MS_PUBLIC_LINE}\n${MS_PUBLIC_LINE}`],
        ['not base64', 'RW!!'],
        ['too short', 'RWTJEPQC'],
    ])('a public key: %s', (_name, text) => {
        expect(error(() => parseMinisignPublic(text))).not.toBe('no error');
        expect(error(() => parseMinisignPublic(text))).not.toMatch(/^other/);
    });
});

const minisign = spawnSync('minisign', ['-v']).error ? null : 'minisign';
describe.skipIf(!minisign)('with the real minisign', () => {
    const dir = mkdtempSync(join(tmpdir(), 'minisign-'));
    const run = (args: string[]) => spawnSync('minisign', args, { encoding: 'utf8' });

    it('accepts a signature made here, with the public key file made here', async () => {
        const trustedComment = 'made by the page';
        const made = await signMinisign(message, seed, { trustedComment });
        writeFileSync(join(dir, 'msg'), message);
        writeFileSync(join(dir, 'msg.minisig'), made.armored);
        writeFileSync(join(dir, 'key.pub'), made.publicFile);
        const result = run(['-V', '-p', join(dir, 'key.pub'), '-m', join(dir, 'msg')]);
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout).toContain(`Trusted comment: ${trustedComment}`);
    });

    it('refuses a signature made here when the message or the trusted comment is changed', async () => {
        const made = await signMinisign(message, seed, { trustedComment: 'original' });
        writeFileSync(join(dir, 'other'), 'hello world');
        writeFileSync(join(dir, 'other.minisig'), made.armored);
        writeFileSync(join(dir, 'other.pub'), made.publicFile);
        expect(run(['-V', '-p', join(dir, 'other.pub'), '-m', join(dir, 'other')]).status).not.toBe(0);
        writeFileSync(join(dir, 'edited'), message);
        writeFileSync(join(dir, 'edited.minisig'), made.armored.replace('original', 'edited'));
        expect(run(['-V', '-p', join(dir, 'other.pub'), '-m', join(dir, 'edited')]).status).not.toBe(0);
    });
});
