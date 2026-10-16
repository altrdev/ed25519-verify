/**
 * minisign (https://jedisct1.github.io/minisign/): a public key `RW…` and a signature file of four lines
 *
 *     untrusted comment: <anything>                      not signed: anyone can change it
 *     base64( "ED" | key id (8 bytes) | signature (64) )  "ED": the BLAKE2b-512 hash of the message is signed; "Ed" (old): the message
 *     trusted comment: <text>                            signed, but only together with the signature above
 *     base64( global signature (64) )                    over  signature | trusted comment
 *
 * The key id only says which key made it (it is no part of the cryptography); it is how a verifier notices that it was given the wrong key.
 * Pure functions: the screen is in MinisignPanel.tsx.
 */
import * as ed from '@noble/ed25519';
import { blake2b512 } from './blake2b';
import { bytesToBase64, bytesToHex, parseBase64, parseHex } from './bytes';

export class MinisignError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'MinisignError';
    }
}

export type MinisignAlgorithm = 'Ed' | 'ED';

const encoder = new TextEncoder();
const SIGNATURE_COMMENT = 'untrusted comment: ';
const TRUSTED_COMMENT = 'trusted comment: ';

const concat = (...parts: Uint8Array[]): Uint8Array => {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
};

/** The key id as minisign prints it: the 8 bytes in the file, read as a little-endian number, in upper-case hex. */
export const keyIdText = (keyId: Uint8Array): string => bytesToHex(Uint8Array.from(keyId).reverse()).toUpperCase();

/** The inverse of `keyIdText`: 16 hex digits. */
export function parseKeyId(text: string): Uint8Array {
    const bytes = /^[0-9a-f]{16}$/i.test(text.trim()) ? parseHex(text.trim()) : null;
    if (!bytes) throw new MinisignError('A key ID is 16 hex digits, as in "minisign public key B74960C202F410C9".');
    return bytes.reverse();
}

/** An id for a key that has none (a plain Ed25519 key): the start of the BLAKE2b hash of the public key, so that it is always the same. */
export const deriveKeyId = (publicKey: Uint8Array): Uint8Array => blake2b512(publicKey).slice(0, 8);

const lines = (text: string) => {
    const all = text.split(/\r?\n/);
    while (all.length && all[all.length - 1].trim() === '') all.pop();
    while (all.length && all[0].trim() === '') all.shift();
    return all;
};

export interface MinisignPublic {
    keyId: Uint8Array;
    publicKey: Uint8Array;
}

/** Does this text look like a minisign public key (a `.pub` file, or just its `RW…` line)? Other texts are keys in other formats. */
export const looksLikeMinisignPublic = (text: string): boolean => {
    const all = lines(text);
    return (
        (all.length === 1 || (all.length === 2 && all[0].startsWith('untrusted comment:'))) &&
        /^RW[A-Za-z0-9+/]{54}$/.test(all[all.length - 1].trim())
    );
};

/** Reads a minisign public key: the file (comment line + key line) or the key line alone. */
export function parseMinisignPublic(text: string): MinisignPublic {
    const all = lines(text);
    if (all.length === 2 && all[0].startsWith('untrusted comment:')) all.shift();
    if (all.length !== 1)
        throw new MinisignError('A minisign public key is one line starting with "RW", optionally after its "untrusted comment:" line.');
    const data = parseBase64(all[0].trim());
    if (data?.length !== 42) {
        throw new MinisignError(
            `The minisign public key has ${data ? `${data.length} bytes` : 'invalid base64'}: it should be 42 bytes (a 56-character text starting with "RW").`,
        );
    }
    if (String.fromCharCode(data[0], data[1]) !== 'Ed')
        throw new MinisignError('The key is not an Ed25519 minisign key (its algorithm is not "Ed").');
    return { keyId: data.slice(2, 10), publicKey: data.slice(10) };
}

export interface ParsedMinisign {
    untrustedComment: string;
    algorithm: MinisignAlgorithm;
    keyId: Uint8Array;
    /** 64 bytes, over the message (`Ed`) or over its BLAKE2b-512 hash (`ED`) */
    signature: Uint8Array;
    trustedComment: string;
    /** 64 bytes, over `signature | trusted comment` */
    globalSignature: Uint8Array;
}

/** Reads a minisign signature file (`.minisig`). */
export function parseMinisign(text: string): ParsedMinisign {
    const all = lines(text);
    if (all.length !== 4 || !all[0].startsWith('untrusted comment:') || !all[2].startsWith('trusted comment:')) {
        throw new MinisignError(
            'A minisign signature has four lines: "untrusted comment: …", the signature, "trusted comment: …" and the signature of the comment.',
        );
    }
    const body = parseBase64(all[1].trim());
    if (!body) throw new MinisignError('The second line (the signature) is not valid base64.');
    if (body.length !== 74) throw new MinisignError(`The signature line has ${body.length} bytes, a minisign one has 74 (2 + 8 + 64).`);
    const algorithm = String.fromCharCode(body[0], body[1]);
    if (algorithm !== 'Ed' && algorithm !== 'ED')
        throw new MinisignError(
            `The signature algorithm "${algorithm.replace(/[^\x20-\x7e]/g, '?')}" is not known: expected "ED" or "Ed".`,
        );
    const globalSignature = parseBase64(all[3].trim());
    if (!globalSignature) throw new MinisignError('The last line (the signature of the trusted comment) is not valid base64.');
    if (globalSignature.length !== 64)
        throw new MinisignError(`The signature of the trusted comment has ${globalSignature.length} bytes, it should have 64.`);
    return {
        untrustedComment: all[0].slice('untrusted comment:'.length).replace(/^ /, ''),
        algorithm,
        keyId: body.slice(2, 10),
        signature: body.slice(10),
        trustedComment: all[2].slice('trusted comment:'.length).replace(/^ /, ''),
        globalSignature,
    };
}

/** What the first signature is made over: the message for `Ed`, its BLAKE2b-512 hash for `ED`. */
export const signedBytes = (algorithm: MinisignAlgorithm, message: Uint8Array): Uint8Array =>
    algorithm === 'ED' ? blake2b512(message) : message;

/** What the signature of the trusted comment is made over: the signature, then the comment (without its label). */
export const commentSignedBytes = (signature: Uint8Array, trustedComment: string): Uint8Array =>
    concat(signature, encoder.encode(trustedComment));

export function encodeMinisign(parts: {
    algorithm: MinisignAlgorithm;
    keyId: Uint8Array;
    signature: Uint8Array;
    trustedComment: string;
    globalSignature: Uint8Array;
    untrustedComment?: string;
}): string {
    return [
        `${SIGNATURE_COMMENT}${parts.untrustedComment ?? 'signature from minisign secret key'}`,
        bytesToBase64(concat(encoder.encode(parts.algorithm), parts.keyId, parts.signature)),
        `${TRUSTED_COMMENT}${parts.trustedComment}`,
        bytesToBase64(parts.globalSignature),
        '',
    ].join('\n');
}

/** A public key as minisign writes it: the comment with the key id, and the `RW…` line. */
export function encodeMinisignPublic({ keyId, publicKey }: MinisignPublic): string {
    return `untrusted comment: minisign public key ${keyIdText(keyId)}\n${bytesToBase64(concat(encoder.encode('Ed'), keyId, publicKey))}\n`;
}

/** What the trusted comment may hold: one line. */
export function checkTrustedComment(comment: string): void {
    if (/[\r\n]/.test(comment)) throw new MinisignError('The trusted comment is one line: it cannot contain line breaks.');
}

/** Signs the way `minisign -S` does (the BLAKE2b-hashed form, "ED"). Without a key id one is derived from the key. */
export async function signMinisign(
    message: Uint8Array,
    seed: Uint8Array,
    options: { trustedComment: string; keyId?: Uint8Array },
): Promise<{ armored: string; publicFile: string; keyId: Uint8Array; publicKey: Uint8Array }> {
    checkTrustedComment(options.trustedComment);
    const publicKey = await ed.getPublicKeyAsync(seed);
    const keyId = options.keyId ?? deriveKeyId(publicKey);
    const signature = await ed.signAsync(signedBytes('ED', message), seed);
    const globalSignature = await ed.signAsync(commentSignedBytes(signature, options.trustedComment), seed);
    return {
        armored: encodeMinisign({ algorithm: 'ED', keyId, signature, trustedComment: options.trustedComment, globalSignature }),
        publicFile: encodeMinisignPublic({ keyId, publicKey }),
        keyId,
        publicKey,
    };
}
