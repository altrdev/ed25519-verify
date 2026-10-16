import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { bytesToBase64, bytesToHex } from '../bytes';
import { parseStructuredKey } from '../keyformats';
import { checkNamespace, encodeSshsig, fingerprint, parseSshsig, signedData, signedDataOf, signSshsig, SshsigError } from '../sshsig';
import {
    SSH_FINGERPRINT,
    SSH_MESSAGE,
    SSH_PRIVATE,
    SSH_PUBLIC,
    SSH_SIG_FILE_SHA256,
    SSH_SIG_FILE_SHA512,
    SSH_SIG_GIT_SHA256,
} from './fixtures/sshsig';

const message = new TextEncoder().encode(SSH_MESSAGE);
const publicKey = parseStructuredKey(SSH_PUBLIC).publicKey as Uint8Array;
const seed = parseStructuredKey(SSH_PRIVATE).privateKey as Uint8Array;
const error = (build: () => unknown) => {
    try {
        build();
    } catch (e) {
        return e instanceof SshsigError ? e.message : `other: ${e}`;
    }
    return 'no error';
};
const same = (a: Uint8Array, b: Uint8Array) => expect(bytesToHex(a)).toBe(bytesToHex(b));

describe('signatures made by OpenSSH', () => {
    it.each([
        ['file', 'sha512', SSH_SIG_FILE_SHA512],
        ['file', 'sha256', SSH_SIG_FILE_SHA256],
        ['git', 'sha256', SSH_SIG_GIT_SHA256],
    ] as const)('namespace %s, %s: parsed, and verified over the structure that is signed', async (namespace, hashAlgorithm, armored) => {
        const parsed = parseSshsig(armored);
        expect(parsed).toMatchObject({ namespace, hashAlgorithm });
        same(parsed.publicKey, publicKey);
        expect(await ed.verifyAsync(parsed.signature, await signedDataOf(parsed, message), publicKey, { zip215: false })).toBe(true);
    });

    it('is not valid for another message, namespace or hash', async () => {
        const parsed = parseSshsig(SSH_SIG_FILE_SHA512);
        const check = async (data: Uint8Array) => ed.verifyAsync(parsed.signature, data, publicKey, { zip215: false });
        expect(await check(await signedData(new TextEncoder().encode('hello world'), parsed))).toBe(false); // without the newline
        expect(await check(await signedData(message, { ...parsed, namespace: 'git' }))).toBe(false);
        expect(await check(await signedData(message, { ...parsed, hashAlgorithm: 'sha256' }))).toBe(false);
    });

    it('has the fingerprint that ssh-keygen shows', async () => {
        expect(await fingerprint(publicKey)).toBe(SSH_FINGERPRINT);
    });
});

describe('signing', () => {
    it('gives, byte for byte, the file that ssh-keygen -Y sign wrote (Ed25519 is deterministic)', async () => {
        expect((await signSshsig(message, seed, { namespace: 'file', hashAlgorithm: 'sha512' })).armored).toBe(SSH_SIG_FILE_SHA512);
        expect((await signSshsig(message, seed, { namespace: 'file', hashAlgorithm: 'sha256' })).armored).toBe(SSH_SIG_FILE_SHA256);
        expect((await signSshsig(message, seed, { namespace: 'git', hashAlgorithm: 'sha256' })).armored).toBe(SSH_SIG_GIT_SHA256);
    });

    it('round trips random messages and namespaces', async () => {
        for (const namespace of ['file', 'git', 'email', 'my-app@example.com']) {
            for (const hashAlgorithm of ['sha256', 'sha512'] as const) {
                const data = crypto.getRandomValues(new Uint8Array(Math.floor(Math.random() * 3000)));
                const { armored } = await signSshsig(data, seed, { namespace, hashAlgorithm });
                const parsed = parseSshsig(armored);
                expect(parsed.namespace).toBe(namespace);
                expect(await ed.verifyAsync(parsed.signature, await signedDataOf(parsed, data), publicKey, { zip215: false })).toBe(true);
            }
        }
    });

    const hasSsh = spawnSync('ssh-keygen', ['-?']).error === undefined;
    it.skipIf(!hasSsh)('is accepted by ssh-keygen, which knows nothing about this code', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'sshsig-'));
        const signers = join(dir, 'allowed_signers');
        writeFileSync(signers, `fixture@example ${SSH_PUBLIC.split(' ').slice(0, 2).join(' ')}\n`);
        for (const [namespace, hashAlgorithm] of [
            ['file', 'sha512'],
            ['git', 'sha256'],
            ['email', 'sha512'],
        ] as const) {
            const data = crypto.getRandomValues(new Uint8Array(500));
            const signature = join(dir, `${namespace}.sig`);
            writeFileSync(signature, (await signSshsig(data, seed, { namespace, hashAlgorithm })).armored);
            const result = spawnSync(
                'ssh-keygen',
                ['-Y', 'verify', '-f', signers, '-I', 'fixture@example', '-n', namespace, '-s', signature],
                {
                    input: Buffer.from(data),
                    encoding: 'utf8',
                },
            );
            expect(result.status, result.stderr + result.stdout).toBe(0);
            expect(result.stdout).toContain(SSH_FINGERPRINT);
            // and it refuses the same file under another namespace
            const other = spawnSync(
                'ssh-keygen',
                ['-Y', 'verify', '-f', signers, '-I', 'fixture@example', '-n', 'other', '-s', signature],
                { input: Buffer.from(data) },
            );
            expect(other.status).not.toBe(0);
        }
    });
});

describe('a signature that cannot be used', () => {
    const body = (...parts: number[][]) => Uint8Array.from(parts.flat());
    const str = (text: string) => [0, 0, 0, text.length, ...new TextEncoder().encode(text)];
    const wrap = (data: Uint8Array) => `-----BEGIN SSH SIGNATURE-----\n${bytesToBase64(data)}\n-----END SSH SIGNATURE-----`;
    const blob = (keyType: string, version = 1, hash = 'sha512', trailing: number[] = []) =>
        wrap(
            body(
                [...new TextEncoder().encode('SSHSIG')],
                [0, 0, 0, version],
                [0, 0, 0, 51 - 11 + keyType.length, ...str(keyType), ...str('x'.repeat(32))],
                str('file'),
                str(''),
                str(hash),
                [0, 0, 0, 83, ...str('ssh-ed25519'), 0, 0, 0, 64, ...new Array(64).fill(1)],
                trailing,
            ),
        );

    it('is explained', () => {
        expect(error(() => parseSshsig('not a signature'))).toMatch(/starts with "-----BEGIN SSH SIGNATURE-----"/);
        expect(error(() => parseSshsig('-----BEGIN SSH SIGNATURE-----\n!!!\n-----END SSH SIGNATURE-----'))).toMatch(/not valid base64/);
        expect(error(() => parseSshsig(wrap(new TextEncoder().encode('NOTSSH at all'))))).toMatch(/SSHSIG" marker is missing/);
        expect(error(() => parseSshsig(wrap(new TextEncoder().encode('SSHSIG'))))).toMatch(/cut short/);
        expect(error(() => parseSshsig(SSH_SIG_FILE_SHA512.replace(/\n[^\n]+\n-----END/, '\n-----END')))).toMatch(
            /cut short|not valid base64|unexpected/,
        );
    });

    it('is told apart by its version, key type, hash and trailing data', () => {
        expect(error(() => parseSshsig(blob('ssh-ed25519', 2)))).toMatch(/version 2/);
        expect(error(() => parseSshsig(blob('ssh-rsa')))).toMatch(/"ssh-rsa" key, only ssh-ed25519/);
        expect(error(() => parseSshsig(blob('sk-ssh-ed25519@openssh.com')))).toMatch(/security-key/);
        expect(error(() => parseSshsig(blob('ssh-ed25519', 1, 'sha1')))).toMatch(/"sha1": only sha256 and sha512/);
        expect(error(() => parseSshsig(blob('ssh-ed25519', 1, 'sha512', [9])))).toMatch(/unexpected data/);
    });

    it('accepts a signature copied out of a git commit, whose lines start with a space', () => {
        const indented = SSH_SIG_GIT_SHA256.split('\n')
            .map((line) => (line ? ` ${line}` : line))
            .join('\n');
        expect(parseSshsig(indented).namespace).toBe('git');
    });

    it('checks the namespace it is asked to write', () => {
        expect(error(() => checkNamespace('file'))).toBe('no error');
        expect(error(() => checkNamespace(''))).toMatch(/required/);
        expect(error(() => checkNamespace('a b'))).toMatch(/spaces or commas/);
        expect(error(() => checkNamespace('a,b'))).toMatch(/spaces or commas/);
    });

    it('is written in lines of 70 characters', () => {
        const armored = encodeSshsig({ publicKey, namespace: 'file', hashAlgorithm: 'sha512', signature: new Uint8Array(64) });
        for (const line of armored.split('\n').slice(1, -3)) expect(line).toHaveLength(70);
    });
});
