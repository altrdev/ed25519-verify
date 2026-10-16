/**
 * The ways a key, a signature or a message can be written as plain text: hex, base64, base58, base32, a list of numbers.
 * Each codec turns bytes into text and back; `readings()` tells how a pasted text can be read.
 *
 * Containers that carry more than the bytes (PEM, OpenSSH, JWK) live in keyformats.ts.
 */
import { bytesToBase64, bytesToHex, parseBase64, parseHex } from './bytes';
import type { RawFormat } from './enum';

export interface Codec {
    id: RawFormat;
    label: string;
    encode(bytes: Uint8Array): string;
    /** the bytes, or null when the text is not written in this format */
    decode(text: string): Uint8Array | null;
}

/* ------------------------------------------------------------------ base58 */

// Bitcoin alphabet: no 0, O, I, l. Leading zero bytes are written as leading '1's (as Bitcoin, Solana, IPFS do).
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function encodeBase58(bytes: Uint8Array): string {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    const digits: number[] = []; // little endian
    for (let i = zeros; i < bytes.length; i++) {
        let carry = bytes[i];
        for (let j = 0; j < digits.length; j++) {
            carry += digits[j] * 256;
            digits[j] = carry % 58;
            carry = Math.floor(carry / 58);
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = Math.floor(carry / 58);
        }
    }
    return '1'.repeat(zeros) + digits.reverse().map((d) => BASE58[d]).join('');
}

export function decodeBase58(text: string): Uint8Array | null {
    let zeros = 0;
    while (zeros < text.length && text[zeros] === '1') zeros++;
    const bytes: number[] = []; // little endian
    for (let i = zeros; i < text.length; i++) {
        const value = BASE58.indexOf(text[i]);
        if (value < 0) return null;
        let carry = value;
        for (let j = 0; j < bytes.length; j++) {
            carry += bytes[j] * 58;
            bytes[j] = carry & 0xff;
            carry >>= 8;
        }
        while (carry > 0) {
            bytes.push(carry & 0xff);
            carry >>= 8;
        }
    }
    return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes.reverse()]);
}

/* ------------------------------------------------------------------ base32 */

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // RFC 4648

export function encodeBase32(bytes: Uint8Array, padded = false): string {
    let out = '';
    let buffer = 0;
    let bits = 0;
    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += BASE32[(buffer >>> (bits - 5)) & 31];
            bits -= 5;
        }
        buffer &= (1 << bits) - 1;
    }
    if (bits > 0) out += BASE32[(buffer << (5 - bits)) & 31];
    return padded ? out.padEnd(Math.ceil(out.length / 8) * 8, '=') : out;
}

/** Upper or lower case (not mixed), padding optional. Leftover bits must be zero, as the RFC asks. */
export function decodeBase32(text: string): Uint8Array | null {
    const body = text.replace(/=+$/, '');
    if (!body || !(/^[A-Z2-7]+$/.test(body) || /^[a-z2-7]+$/.test(body))) return null;
    if (![0, 2, 4, 5, 7].includes(body.length % 8)) return null;
    const out: number[] = [];
    let buffer = 0;
    let bits = 0;
    for (const char of body.toUpperCase()) {
        buffer = (buffer << 5) | BASE32.indexOf(char);
        bits += 5;
        if (bits >= 8) {
            out.push((buffer >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
        buffer &= (1 << bits) - 1;
    }
    return buffer === 0 ? Uint8Array.from(out) : null;
}

/* ------------------------------------------------------------------ others */

/** `[12, 34, 56]`: how a Solana keypair file, Rust, Go, C or JavaScript show bytes. Also accepts `{0x0c, 0x22}` and bare lists. */
export function decodeByteArray(text: string): Uint8Array | null {
    const match = /^[[{]([\s\S]*)[\]}]$/.exec(text.trim());
    if (!match) return null;
    const items = match[1].split(/[\s,]+/).filter(Boolean);
    const bytes: number[] = [];
    for (const item of items) {
        if (!/^(?:0x[0-9a-f]{1,2}|\d{1,3})$/i.test(item)) return null;
        const value = Number(item);
        if (value > 255) return null;
        bytes.push(value);
    }
    return bytes.length > 0 ? Uint8Array.from(bytes) : null;
}

export const CODECS: Record<RawFormat, Codec> = {
    hex: { id: 'hex', label: 'Hex', encode: bytesToHex, decode: (t) => parseHex(t.replace(/^0x/i, '')) },
    hex0x: {
        id: 'hex0x',
        label: 'Hex (0x…)',
        encode: (b) => `0x${bytesToHex(b)}`,
        decode: (t) => (/^0x/i.test(t) ? parseHex(t.slice(2)) : null),
    },
    base64: { id: 'base64', label: 'Base64', encode: bytesToBase64, decode: parseBase64 },
    base64url: {
        id: 'base64url',
        label: 'Base64url',
        encode: (b) => bytesToBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        decode: parseBase64,
    },
    base58: { id: 'base58', label: 'Base58', encode: encodeBase58, decode: decodeBase58 },
    base32: { id: 'base32', label: 'Base32', encode: (b) => encodeBase32(b), decode: decodeBase32 },
    bytes: { id: 'bytes', label: 'Byte array', encode: (b) => `[${Array.from(b).join(', ')}]`, decode: decodeByteArray },
};

export const encodeAs = (bytes: Uint8Array, format: RawFormat): string => CODECS[format].encode(bytes);

/* --------------------------------------------------------------- detection */

export interface Reading {
    format: RawFormat;
    bytes: Uint8Array;
}

/**
 * Every way a pasted text can be read as bytes. Whitespace is ignored (a paste wraps lines).
 *
 * The notations that cannot be mistaken for anything else win at once: a list of numbers, a `0x` number, a text made of hex
 * digits only (a real base64 or base58 value is never made of hex digits only, so a truncated hex key stays a hex key).
 * Otherwise base64, base58 and base32 are all candidates: the caller keeps the ones of the right size, and when more than one
 * is left the text is ambiguous.
 */
export function readings(text: string): Reading[] {
    const trimmed = text.trim();
    if (/^[[{]/.test(trimmed)) {
        const bytes = decodeByteArray(trimmed);
        return bytes ? [{ format: 'bytes', bytes }] : [];
    }
    const value = trimmed.replace(/\s+/g, '');
    if (!value) return [];
    if (/^0x/i.test(value)) {
        const bytes = CODECS.hex0x.decode(value);
        if (bytes) return [{ format: 'hex0x', bytes }];
        // not a 0x number after all: a base64 text begins with "0x" or "0X" about once in 2000 (its first two characters)
    }
    if (/^[0-9a-f]+$/i.test(value)) {
        const bytes = parseHex(value);
        return bytes ? [{ format: 'hex', bytes }] : [];
    }

    const found: Reading[] = [];
    const base64 = parseBase64(value);
    if (base64) found.push({ format: /[-_]/.test(value) ? 'base64url' : 'base64', bytes: base64 });
    const base58 = decodeBase58(value);
    if (base58) found.push({ format: 'base58', bytes: base58 });
    const base32 = decodeBase32(value);
    if (base32) found.push({ format: 'base32', bytes: base32 });
    return found;
}
