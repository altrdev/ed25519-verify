/**
 * Lists of SSH public keys with their options: `authorized_keys` (`[options] ssh-ed25519 AAAA… comment`) and `allowed_signers`, the file
 * `ssh-keygen -Y verify` reads (`principals [options] ssh-ed25519 AAAA… comment`, for example `alice@example.com namespaces="git" ssh-ed25519 AAAA…`).
 * A signature carries the key that made it, so the entry that matches it is found by the key; the options that restrict an entry are then
 * applied (namespaces) or reported (the ones this page does not check). Pure functions.
 */
import { parseBase64 } from './bytes';

export interface ListedKey {
    /** its line in the text, from 1 */
    line: number;
    /** who the key belongs to (allowed_signers); empty in an authorized_keys line */
    principals: string[];
    options: string[];
    /** the namespaces the entry allows (`namespaces="git,file"`); null: all */
    namespaces: string[] | null;
    comment: string;
    publicKey: Uint8Array;
}

export interface KeyList {
    /** the ssh-ed25519 entries */
    keys: ListedKey[];
    /** entries of other key types, or `cert-authority` ones (their key signs certificates, it is no signer) */
    ignored: number;
}

const KEY_TYPE = /^(ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)$/;
const FLAGS = new Set([
    'restrict',
    'cert-authority',
    'agent-forwarding',
    'no-agent-forwarding',
    'port-forwarding',
    'no-port-forwarding',
    'pty',
    'no-pty',
    'user-rc',
    'no-user-rc',
    'x11-forwarding',
    'no-x11-forwarding',
    'touch-required',
    'no-touch-required',
    'verify-required',
]);
const VALUED = new Set([
    'command',
    'environment',
    'expiry-time',
    'from',
    'namespaces',
    'permitlisten',
    'permitopen',
    'principals',
    'tunnel',
    'valid-after',
    'valid-before',
]);

/** Words separated by spaces, where a double-quoted part (an option value) may hold spaces. */
function words(line: string): string[] {
    const out: string[] = [];
    let current = '';
    let quoted = false;
    for (const character of line) {
        if (character === '"') quoted = !quoted;
        if (/\s/.test(character) && !quoted) {
            if (current) out.push(current);
            current = '';
        } else {
            current += character;
        }
    }
    if (current) out.push(current);
    return out;
}

const isOption = (word: string) =>
    word.split(',').every((piece) => {
        const name = piece.split('=')[0].toLowerCase();
        return piece.includes('=') ? VALUED.has(name) : FLAGS.has(name);
    });

const optionsOf = (word: string): string[] => {
    // split on the commas that are outside the quotes
    const out: string[] = [];
    let current = '';
    let quoted = false;
    for (const character of word) {
        if (character === '"') quoted = !quoted;
        if (character === ',' && !quoted) {
            out.push(current);
            current = '';
        } else {
            current += character;
        }
    }
    out.push(current);
    return out;
};

const unquote = (value: string) => value.replace(/^"(.*)"$/, '$1');

/** Where the key type is in a line: the first word that names one and is followed by base64. -1: this is no key line. */
function keyTypeIndex(parts: string[]): number {
    return parts.findIndex((part, i) => KEY_TYPE.test(part) && i + 1 < parts.length && /^[A-Za-z0-9+/]+={0,2}$/.test(parts[i + 1]));
}

const contentLines = (text: string) =>
    text
        .split(/\r?\n/)
        .map((raw, index) => ({ line: index + 1, text: raw.trim() }))
        .filter(({ text: line }) => line !== '' && !line.startsWith('#'));

/**
 * Is this text a list of keys, or a key with something before it (principals, options), rather than a single plain `ssh-ed25519 AAAA…`
 * line? A text that is a plain key is read by the usual key reader.
 */
export function looksLikeKeyList(text: string): boolean {
    const lines = contentLines(text);
    if (lines.length === 0 || text.includes('-----BEGIN')) return false;
    const found = lines.map(({ text: line }) => keyTypeIndex(words(line)));
    if (lines.length === 1) return found[0] > 0;
    return found.some((index) => index >= 0);
}

const blobKey = (data: string): Uint8Array | null => {
    const blob = parseBase64(data);
    if (!blob) return null;
    const read = (offset: number): [Uint8Array, number] | null => {
        if (offset + 4 > blob.length) return null;
        const length = blob[offset] * 2 ** 24 + (blob[offset + 1] << 16) + (blob[offset + 2] << 8) + blob[offset + 3];
        return offset + 4 + length > blob.length ? null : [blob.slice(offset + 4, offset + 4 + length), offset + 4 + length];
    };
    const type = read(0);
    if (!type || new TextDecoder().decode(type[0]) !== 'ssh-ed25519') return null;
    const key = read(type[1]);
    return key?.[0].length === 32 ? key[0] : null;
};

export class KeyListError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'KeyListError';
    }
}

/** Reads the lines of an `authorized_keys` / `allowed_signers` text. Lines that are not keys are errors, not skipped silently. */
export function parseKeyList(text: string): KeyList {
    const keys: ListedKey[] = [];
    let ignored = 0;
    for (const { line, text: content } of contentLines(text)) {
        const parts = words(content);
        const at = keyTypeIndex(parts);
        if (at < 0) throw new KeyListError(`Line ${line} is not a key: expected "[principals] [options] ssh-ed25519 AAAA… [comment]".`);
        const before = parts.slice(0, at);
        // allowed_signers starts with the principals; an authorized_keys line starts with the options (or with the key)
        const principals = before.length > 0 && !isOption(before[0]) ? before[0].split(',').map(unquote) : [];
        const options = before.slice(principals.length > 0 ? 1 : 0).flatMap(optionsOf);
        if (options.some((option) => option.toLowerCase() === 'cert-authority') || parts[at] !== 'ssh-ed25519') {
            ignored++;
            continue;
        }
        const publicKey = blobKey(parts[at + 1]);
        if (!publicKey) throw new KeyListError(`The key on line ${line} is not a valid ssh-ed25519 key.`);
        const namespaceOption = options.find((option) => option.toLowerCase().startsWith('namespaces='));
        keys.push({
            line,
            principals,
            options,
            namespaces: namespaceOption ? unquote(namespaceOption.slice('namespaces='.length)).split(',') : null,
            comment: parts.slice(at + 2).join(' '),
            publicKey,
        });
    }
    return { keys, ignored };
}

/** Options that restrict an entry that this page does not check (the ones of the signature's time, for example). */
export const unchecked = (key: ListedKey): string[] =>
    key.options.filter((option) => /^(valid-after|valid-before|expiry-time|from)=/i.test(option)).map((option) => option.split('=')[0]);

/** Who an entry is, for the messages. */
export const entryName = (key: ListedKey): string =>
    key.principals.length ? key.principals.join(', ') : key.comment || `line ${key.line}`;

/** Does the entry allow a signature made for this namespace? Without a `namespaces` option, every namespace is allowed. */
export const allowsNamespace = (key: ListedKey, namespace: string): boolean => {
    if (!key.namespaces) return true;
    return key.namespaces.some((pattern) =>
        new RegExp(
            `^${pattern
                .replace(/[.+^${}()|[\]\\]/g, '\\$&')
                .replace(/\*/g, '.*')
                .replace(/\?/g, '.')}$`,
        ).test(namespace),
    );
};
