import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex } from '../bytes';
import { detectKeyFormat, KeyFormatError, parseStructuredKey } from '../keyformats';
import { allowsNamespace, entryName, looksLikeKeyList, parseKeyList, unchecked } from '../sshkeys';
import { SSH_MESSAGE, SSH_PUBLIC, SSH_SIG_FILE_SHA256, SSH_SIG_GIT_SHA256 } from './fixtures/sshsig';

const BOB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHutfARIAKac1UBklevRYkl5TpRap6tVZU4m28FXKepr bob-key';
const ALLOWED = `# who signs what\nalice@example.com namespaces="git" ${SSH_PUBLIC}\n\nbob@example.com,robert@example.com ${BOB}\n`;
const key = (line: string) => line.split(' ')[1];
const error = (build: () => unknown) => {
    try {
        build();
    } catch (e) {
        return e instanceof Error ? e.message : `other: ${e}`;
    }
    return 'no error';
};

describe('what is a list of keys', () => {
    it('is told from a plain key, which the usual reader takes', () => {
        expect(looksLikeKeyList(SSH_PUBLIC)).toBe(false);
        expect(looksLikeKeyList(`${SSH_PUBLIC}\n`)).toBe(false);
        expect(looksLikeKeyList('')).toBe(false);
        expect(looksLikeKeyList('00ff10')).toBe(false);
        expect(looksLikeKeyList('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----')).toBe(false);
        expect(looksLikeKeyList(`alice@example.com ${SSH_PUBLIC}`)).toBe(true);
        expect(looksLikeKeyList(`no-pty ${SSH_PUBLIC}`)).toBe(true);
        expect(looksLikeKeyList(`${SSH_PUBLIC}\n${BOB}`)).toBe(true);
        expect(detectKeyFormat(ALLOWED)).toMatch(/SSH key list/);
    });
});

describe('reading allowed_signers and authorized_keys', () => {
    it('reads the principals, the options and the comment of each entry', () => {
        const list = parseKeyList(ALLOWED);
        expect(list.ignored).toBe(0);
        expect(list.keys.map((entry) => [entry.line, entry.principals, entry.namespaces, entry.comment])).toEqual([
            [2, ['alice@example.com'], ['git'], 'fixture@example'],
            [4, ['bob@example.com', 'robert@example.com'], null, 'bob-key'],
        ]);
        expect(entryName(list.keys[1])).toBe('bob@example.com, robert@example.com');
    });

    it('reads authorized_keys lines: options and no principals, quoted values with spaces', () => {
        const list = parseKeyList(`restrict,command="echo a b",from="10.0.0.*" ${SSH_PUBLIC}\n${BOB}`);
        expect(list.keys[0].principals).toEqual([]);
        expect(list.keys[0].options).toEqual(['restrict', 'command="echo a b"', 'from="10.0.0.*"']);
        expect(list.keys[0].comment).toBe('fixture@example');
        expect(unchecked(list.keys[0])).toEqual(['from']);
        expect(entryName(list.keys[1])).toBe('bob-key');
    });

    it('counts what is not a signer: other key types and certificate authorities', () => {
        const list = parseKeyList(
            `ca@example.com cert-authority ${SSH_PUBLIC}\nrsa@example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==\n${BOB}`,
        );
        expect(list.ignored).toBe(2);
        expect(list.keys).toHaveLength(1);
    });

    it('matches namespaces with the patterns of OpenSSH', () => {
        const [entry] = parseKeyList(`a namespaces="git,file*" ${SSH_PUBLIC}`).keys;
        expect([
            entry.namespaces,
            allowsNamespace(entry, 'git'),
            allowsNamespace(entry, 'file'),
            allowsNamespace(entry, 'files-x'),
        ]).toEqual([['git', 'file*'], true, true, true]);
        expect(allowsNamespace(entry, 'email')).toBe(false);
        expect(allowsNamespace(parseKeyList(`a ${SSH_PUBLIC}`).keys[0], 'anything')).toBe(true);
    });

    it('says which line is not a key, and a key that is broken', () => {
        expect(error(() => parseKeyList(`${SSH_PUBLIC}\nthis is not a key`))).toMatch(/Line 2 is not a key/);
        expect(error(() => parseKeyList(`a ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`))).toMatch(/line 1 is not a valid ssh-ed25519 key/);
    });
});

describe('a list where a key is expected', () => {
    it('is the key when there is one, whatever is written before it', () => {
        expect(bytesToHex(parseStructuredKey(`alice@example.com namespaces="git" ${SSH_PUBLIC}`).publicKey!)).toBe(
            bytesToHex(parseStructuredKey(SSH_PUBLIC).publicKey!),
        );
        expect(bytesToHex(parseStructuredKey(`${SSH_PUBLIC}\n${SSH_PUBLIC} again`).publicKey!)).toBe(
            bytesToHex(parseStructuredKey(SSH_PUBLIC).publicKey!),
        );
    });

    it('is refused when it has several different keys, naming them: nothing there says which', () => {
        const message = error(() => parseStructuredKey(ALLOWED));
        expect(message).toContain('has 2 Ed25519 keys');
        expect(message).toContain('alice@example.com');
        expect(message).toContain('bob@example.com, robert@example.com');
        expect(() => parseStructuredKey(ALLOWED)).toThrow(KeyFormatError);
        expect(
            error(() => parseStructuredKey(`a ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==\nb ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==`)),
        ).toMatch(/no ssh-ed25519 key \(2 of another kind\)/);
    });
});

// the reference: what ssh-keygen -Y verify says about the same files and signatures
const hasSsh = spawnSync('ssh-keygen', ['-?']).error === undefined;
describe.skipIf(!hasSsh)('as ssh-keygen -Y verify reads them', () => {
    const dir = mkdtempSync(join(tmpdir(), 'allowed-'));
    writeFileSync(join(dir, 'allowed'), ALLOWED);
    writeFileSync(join(dir, 'file.sig'), SSH_SIG_FILE_SHA256);
    writeFileSync(join(dir, 'git.sig'), SSH_SIG_GIT_SHA256);
    const check = (principal: string, namespace: string, sig: string) =>
        spawnSync('ssh-keygen', ['-Y', 'verify', '-f', join(dir, 'allowed'), '-I', principal, '-n', namespace, '-s', join(dir, sig)], {
            input: SSH_MESSAGE,
            encoding: 'utf8',
        }).status;

    it('agrees on which entry allows which namespace', () => {
        const alice = parseKeyList(ALLOWED).keys[0];
        expect(check('alice@example.com', 'git', 'git.sig')).toBe(0);
        expect(allowsNamespace(alice, 'git')).toBe(true);
        // the same key, a namespace that the entry does not allow: refused by both
        expect(check('alice@example.com', 'file', 'file.sig')).not.toBe(0);
        expect(allowsNamespace(alice, 'file')).toBe(false);
        // another principal does not have the key
        expect(check('bob@example.com', 'git', 'git.sig')).not.toBe(0);
        expect(key(BOB)).not.toBe(key(SSH_PUBLIC));
    });
});
