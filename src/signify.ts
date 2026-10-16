/**
 * signify (OpenBSD, https://man.openbsd.org/signify): the little brother of minisign, with the same two-line files
 *
 *     untrusted comment: <anything>                      not signed: anyone can change it
 *     base64( "Ed" | key number (8 bytes) | key (32) )   a public key
 *     base64( "Ed" | key number (8 bytes) | signature (64) )   a signature, over the message itself (no hash, no trusted comment)
 *
 * The key number only says which key made the signature; it is how a verifier notices that it was given the wrong key.
 * Pure functions: the screen is in SignifyPanel.tsx.
 */
import * as ed from '@noble/ed25519';
import { bytesToBase64, bytesToHex, parseBase64 } from './bytes';
import { deriveKeyId } from './minisign';

export class SignifyError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SignifyError';
    }
}

const COMMENT = 'untrusted comment:';
const encoder = new TextEncoder();

const concat = (...parts: Uint8Array[]): Uint8Array => {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
};

const lines = (text: string) => {
    const all = text.split(/\r?\n/);
    while (all.length && all[all.length - 1].trim() === '') all.pop();
    while (all.length && all[0].trim() === '') all.shift();
    return all;
};

/** The key number as a hex string (signify never prints it: this is how it is shown here). */
export const keyNumberText = (keyNumber: Uint8Array): string => bytesToHex(keyNumber);

/** The base64 line of a file, whatever comes before it: the line after the comment, or the only line. */
function body(text: string, what: string): Uint8Array {
    const all = lines(text);
    if (all.length === 2 && all[0].startsWith(COMMENT)) all.shift();
    if (all.length !== 1 || all[0].startsWith(COMMENT))
        throw new SignifyError(`A signify ${what} has two lines: "untrusted comment: …" and the base64 line.`);
    const data = parseBase64(all[0].trim());
    if (!data) throw new SignifyError(`The base64 line of the ${what} is not valid base64.`);
    return data;
}

export interface SignifyPublic {
    keyNumber: Uint8Array;
    publicKey: Uint8Array;
}

/**
 * Does this text look like a signify public key (a `.pub` file, or its line alone)? The layout is the one of a minisign key: either
 * tool can read the key of the other, since the signature is what tells them apart.
 */
export const looksLikeSignifyPublic = (text: string): boolean => {
    const all = lines(text);
    return (
        (all.length === 1 || (all.length === 2 && all[0].startsWith(COMMENT))) && /^RW[A-Za-z0-9+/]{54}$/.test(all[all.length - 1].trim())
    );
};

export function parseSignifyPublic(text: string): SignifyPublic {
    const data = body(text, 'public key');
    if (data.length !== 42)
        throw new SignifyError(
            `The signify public key has ${data.length} bytes, it should have 42 (a 56-character line starting with "RW").`,
        );
    if (String.fromCharCode(data[0], data[1]) !== 'Ed')
        throw new SignifyError('The key is not an Ed25519 signify key (its algorithm is not "Ed").');
    return { keyNumber: data.slice(2, 10), publicKey: data.slice(10) };
}

export interface ParsedSignify {
    untrustedComment: string;
    keyNumber: Uint8Array;
    /** 64 bytes, over the message */
    signature: Uint8Array;
}

/** Does this text look like a signify signature: a comment line and 74 bytes that start with "Ed"? (minisign has four lines.) */
export const looksLikeSignify = (text: string): boolean => {
    const all = lines(text);
    if (all.length !== 2 || !all[0].startsWith(COMMENT) || !/^RW[A-Za-z0-9+/]+={0,2}$/.test(all[1].trim())) return false;
    return parseBase64(all[1].trim())?.length === 74;
};

export function parseSignify(text: string): ParsedSignify {
    const all = lines(text);
    if (all.length === 4 && all[0].startsWith(COMMENT) && all[2].startsWith('trusted comment:'))
        throw new SignifyError('This has a trusted comment: it is a minisign signature, signify has none. Use the minisign format.');
    const data = body(text, 'signature');
    if (data.length !== 74) throw new SignifyError(`The signature line has ${data.length} bytes, a signify one has 74 (2 + 8 + 64).`);
    if (String.fromCharCode(data[0], data[1]) !== 'Ed')
        throw new SignifyError(
            `The signature algorithm "${String.fromCharCode(data[0], data[1]).replace(/[^\x20-\x7e]/g, '?')}" is not known: expected "Ed".`,
        );
    return {
        untrustedComment: all.length === 2 ? all[0].slice(COMMENT.length).replace(/^ /, '') : '',
        keyNumber: data.slice(2, 10),
        signature: data.slice(10),
    };
}

/** A key number for a key that has none (a plain Ed25519 key): derived from the key, so that it is always the same. */
export const deriveKeyNumber = (publicKey: Uint8Array): Uint8Array => deriveKeyId(publicKey);

/** The 16 hex digits of a key number. */
export function parseKeyNumber(text: string): Uint8Array {
    const clean = text.trim();
    if (!/^[0-9a-f]{16}$/i.test(clean)) throw new SignifyError('A key number is 16 hexadecimal digits.');
    return Uint8Array.from(clean.match(/../g) as string[], (pair) => Number.parseInt(pair, 16));
}

export function encodeSignify(parts: { keyNumber: Uint8Array; signature: Uint8Array; untrustedComment?: string }): string {
    return `${COMMENT} ${parts.untrustedComment ?? 'verify with signify.pub'}\n${bytesToBase64(concat(encoder.encode('Ed'), parts.keyNumber, parts.signature))}\n`;
}

export function encodeSignifyPublic({ keyNumber, publicKey }: SignifyPublic): string {
    return `${COMMENT} signify public key\n${bytesToBase64(concat(encoder.encode('Ed'), keyNumber, publicKey))}\n`;
}

/** Signs the way `signify -S` does: the signature over the message itself. Without a key number one is derived from the key. */
export async function signSignify(
    message: Uint8Array,
    seed: Uint8Array,
    options: { keyNumber?: Uint8Array } = {},
): Promise<{ armored: string; publicFile: string; keyNumber: Uint8Array; publicKey: Uint8Array }> {
    const publicKey = await ed.getPublicKeyAsync(seed);
    const keyNumber = options.keyNumber ?? deriveKeyNumber(publicKey);
    const signature = await ed.signAsync(message, seed);
    return {
        armored: encodeSignify({ keyNumber, signature }),
        publicFile: encodeSignifyPublic({ keyNumber, publicKey }),
        keyNumber,
        publicKey,
    };
}
