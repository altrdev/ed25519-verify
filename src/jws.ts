/**
 * JWS compact serialization (RFC 7515) with EdDSA (RFC 8037), which is what a JWT signed with Ed25519 is:
 * `base64url(header).base64url(payload).base64url(signature)`, the signature being over the ASCII text `header.payload`.
 * Only what is certain is accepted: the algorithm must be EdDSA (never "none", never a key chosen by the token), the parts must be
 * base64url as RFC 7515 writes it (no padding), and a header that asks for an extension we do not know (`crit`) is refused.
 * Pure functions: the screen is in JwsPanel.tsx.
 */
import { CODECS } from './codecs';

export class JwsError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'JwsError';
    }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const encodeBase64Url = (bytes: Uint8Array): string => CODECS.base64url.encode(bytes);

/** Strict base64url without padding, as a JWS writes it; null when the text is not. */
export function decodeBase64Url(text: string): Uint8Array | null {
    if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
    const standard = text.replace(/-/g, '+').replace(/_/g, '/');
    try {
        const binary = atob(standard + '='.repeat((4 - (standard.length % 4)) % 4));
        return Uint8Array.from(binary, (char) => char.charCodeAt(0));
    } catch {
        return null;
    }
}

export interface ParsedJws {
    /** the header exactly as written, and as an object */
    headerText: string;
    header: Record<string, unknown>;
    payload: Uint8Array;
    /** the signature (64 bytes) */
    signature: Uint8Array;
    /** what the signature is over: the ASCII text `header.payload` as it is in the token */
    signingInput: Uint8Array;
}

const NAMES = ['header', 'payload', 'signature'];

function utf8(bytes: Uint8Array, what: string): string {
    try {
        return decoder.decode(bytes);
    } catch {
        throw new JwsError(`The ${what} is not valid UTF-8 text.`);
    }
}

/** Parses a token and checks that it is one this tool can verify; throws a JwsError saying what is wrong. */
export function parseJws(token: string): ParsedJws {
    const text = token.trim().replace(/^Bearer\s+/i, '');
    if (!text) throw new JwsError('Paste a token.');
    const parts = text.split('.');
    if (parts.length === 5) throw new JwsError('This is an encrypted token (JWE, five parts), not a signed one.');
    if (parts.length !== 3)
        throw new JwsError(`A signed token has three parts separated by dots (header.payload.signature), this one has ${parts.length}.`);

    const bytes = parts.map((part, i) => {
        if (part.includes('=')) throw new JwsError(`The ${NAMES[i]} has "=" padding: a JWS is written in base64url without padding.`);
        const decoded = decodeBase64Url(part);
        if (!decoded) throw new JwsError(`The ${NAMES[i]} is not base64url (letters, digits, "-" and "_" only).`);
        return decoded;
    });

    const headerText = utf8(bytes[0], 'header');
    let header: unknown;
    try {
        header = JSON.parse(headerText);
    } catch {
        throw new JwsError('The header is not JSON.');
    }
    if (typeof header !== 'object' || header === null || Array.isArray(header)) throw new JwsError('The header must be a JSON object.');
    const fields = header as Record<string, unknown>;

    if (fields.alg === undefined) throw new JwsError('The header has no "alg".');
    if (fields.alg === 'none')
        throw new JwsError('The algorithm is "none": the token is not signed at all, so there is nothing to verify.');
    if (fields.alg !== 'EdDSA') {
        throw new JwsError(`The algorithm is ${JSON.stringify(fields.alg)}: this tool verifies EdDSA (Ed25519) tokens only.`);
    }
    if (fields.crit !== undefined) {
        throw new JwsError('The header has "crit": it requires extensions this tool does not know, so it must not accept the token.');
    }
    if (bytes[2].length !== 64) throw new JwsError(`The signature has ${bytes[2].length} bytes, an Ed25519 signature has 64.`);

    return {
        headerText,
        header: fields,
        payload: bytes[1],
        signature: bytes[2],
        signingInput: encoder.encode(`${parts[0]}.${parts[1]}`),
    };
}

/** What the payload says, when it is text, and when it is a JSON object its claims about time. */
export interface PayloadInfo {
    text: string | null;
    /** the payload as pretty JSON, when it is a JSON object */
    json: string | null;
    exp?: number;
    nbf?: number;
    iat?: number;
}

export function describePayload(payload: Uint8Array): PayloadInfo {
    let text: string;
    try {
        text = decoder.decode(payload);
    } catch {
        return { text: null, json: null };
    }
    try {
        const value = JSON.parse(text);
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            const number = (key: string) =>
                typeof value[key] === 'number' && Number.isFinite(value[key]) ? (value[key] as number) : undefined;
            return { text, json: JSON.stringify(value, null, 2), exp: number('exp'), nbf: number('nbf'), iat: number('iat') };
        }
    } catch {
        // not JSON: a payload can be any text
    }
    return { text, json: null };
}

const date = (seconds: number) => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');

/**
 * Notes on the times of a JWT, compared with `now` (seconds). They do not change the verdict, which is about the signature:
 * a token can be signed correctly and expired.
 */
export function timeNotes({ exp, nbf, iat }: PayloadInfo, now: number): string[] {
    const notes: string[] = [];
    if (exp !== undefined) notes.push(exp <= now ? `Expired: it expired on ${date(exp)}.` : `Expires on ${date(exp)}.`);
    if (nbf !== undefined) notes.push(nbf > now ? `Not valid yet: it starts on ${date(nbf)}.` : `Valid since ${date(nbf)}.`);
    if (iat !== undefined) notes.push(`Issued on ${date(iat)}.`);
    return notes;
}

/** The header of a new token: it must be a JSON object whose "alg" is EdDSA. The text is signed exactly as typed. */
export function checkHeaderToSign(headerText: string): void {
    let header: unknown;
    try {
        header = JSON.parse(headerText);
    } catch {
        throw new JwsError('The header is not JSON.');
    }
    if (typeof header !== 'object' || header === null || Array.isArray(header)) throw new JwsError('The header must be a JSON object.');
    if ((header as Record<string, unknown>).alg !== 'EdDSA') throw new JwsError('The header must say "alg": "EdDSA".');
    if ((header as Record<string, unknown>).crit !== undefined) throw new JwsError('"crit" is not supported.');
}

/** The part of the token that is signed: `base64url(header).base64url(payload)`, from the texts as typed (UTF-8). */
export const signingInputOf = (headerText: string, payloadText: string): string =>
    `${encodeBase64Url(encoder.encode(headerText))}.${encodeBase64Url(encoder.encode(payloadText))}`;

/** Completes a token with the signature of its signing input. */
export const tokenOf = (signingInput: string, signature: Uint8Array): string => `${signingInput}.${encodeBase64Url(signature)}`;
export const bytesOfInput = (signingInput: string): Uint8Array => encoder.encode(signingInput);
