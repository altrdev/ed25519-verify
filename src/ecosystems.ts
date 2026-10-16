/**
 * Ed25519 keys as the ecosystems built on them write them: did:key (W3C), Stellar strkeys, Tor v3 onion addresses and NEAR
 * `ed25519:` keys, plus the Solana keypair file. Each is a few bytes of wrapping around the same 32 bytes, so reading and writing
 * are small enough to live together. Like keyformats.ts and keyfiles.ts it knows nothing about the UI.
 */
import { CODECS, encodeBase32 } from './codecs';
import type { EcosystemFormat } from './enum';
import { sha3_256 } from './sha3';

export const ECOSYSTEM_FORMATS: EcosystemFormat[] = ['didkey', 'stellar', 'onion', 'near', 'solana'];

export const ECOSYSTEM_LABELS: Record<EcosystemFormat, string> = {
    didkey: 'did:key',
    stellar: 'Stellar',
    onion: 'Tor onion',
    near: 'NEAR',
    solana: 'Solana',
};

/** What each ecosystem has for a public key and for a private one (a Tor address is a public key only, did:key too). */
export const ECOSYSTEM_KINDS: Record<EcosystemFormat, { public: boolean; private: boolean }> = {
    didkey: { public: true, private: false },
    stellar: { public: true, private: true },
    onion: { public: true, private: false },
    near: { public: true, private: true },
    solana: { public: false, private: true },
};

/** The key a text holds: a public key, a private one (the 32-byte seed), or both. */
export interface EcosystemKey {
    format: EcosystemFormat;
    publicKey?: Uint8Array;
    privateKey?: Uint8Array;
}

/** The text looks like one of these, but is not a valid key of it. The message says why. */
export class EcosystemError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'EcosystemError';
    }
}

const concat = (...parts: ArrayLike<number>[]): Uint8Array => Uint8Array.from(parts.flatMap((part) => Array.from(part)));
const same = (a: Uint8Array, b: ArrayLike<number>) => a.length === b.length && a.every((value, i) => value === b[i]);

/* ------------------------------------------------------------------ did:key */

// multicodec ed25519-pub (0xed) as a varint: 0xed 0x01; multibase base58btc prefix "z"
const MULTICODEC = [0xed, 0x01];

const encodeDidKey = (publicKey: Uint8Array) => `did:key:z${CODECS.base58.encode(concat(MULTICODEC, publicKey))}`;

function decodeDidKey(text: string): EcosystemKey {
    const encoded = text.slice('did:key:'.length).split(/[#?]/)[0]; // a verification method (…#z6Mk…) names the same key
    if (!encoded.startsWith('z')) throw new EcosystemError('a did:key is written in base58 (it starts with "z").');
    const bytes = CODECS.base58.decode(encoded.slice(1));
    if (!bytes) throw new EcosystemError('the did:key is not valid base58.');
    if (bytes[0] !== 0xed || bytes[1] !== 0x01) throw new EcosystemError('this did:key is not an Ed25519 key (z6Mk…).');
    if (bytes.length !== 34) throw new EcosystemError(`the did:key holds ${bytes.length - 2} bytes, an Ed25519 key has 32.`);
    return { format: 'didkey', publicKey: bytes.slice(2) };
}

/* ------------------------------------------------------------------ Stellar */

// strkey (SEP-23): base32 of version byte + payload + CRC16-XModem (little endian). G = public key, S = secret seed.
const STELLAR_VERSION = { public: 6 << 3, private: 18 << 3 };

function crc16(data: Uint8Array): number {
    let crc = 0;
    for (const byte of data) {
        crc ^= byte << 8;
        for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
    return crc;
}

function strkey(version: number, payload: Uint8Array): string {
    const body = concat([version], payload);
    const crc = crc16(body);
    return encodeBase32(concat(body, [crc & 255, crc >> 8]));
}

function decodeStellar(text: string): EcosystemKey {
    const bytes = CODECS.base32.decode(text);
    if (bytes?.length !== 35) throw new EcosystemError('the Stellar key is not valid.');
    const crc = crc16(bytes.slice(0, 33));
    if ((crc & 255) !== bytes[33] || crc >> 8 !== bytes[34])
        throw new EcosystemError('the Stellar key has a wrong checksum (is a character mistyped?).');
    if (bytes[0] === STELLAR_VERSION.public) return { format: 'stellar', publicKey: bytes.slice(1, 33) };
    if (bytes[0] === STELLAR_VERSION.private) return { format: 'stellar', privateKey: bytes.slice(1, 33) };
    throw new EcosystemError('this Stellar key is not an account key (G…) or a secret seed (S…).');
}

/* ----------------------------------------------------------------- Tor onion */

// rend-spec-v3: base32(pubkey || checksum || version) + ".onion", checksum = SHA3-256(".onion checksum" || pubkey || version)[:2]
const ONION_VERSION = 3;
const ONION_PREFIX = new TextEncoder().encode('.onion checksum');
const onionChecksum = (publicKey: Uint8Array) => sha3_256(concat(Array.from(ONION_PREFIX), publicKey, [ONION_VERSION])).slice(0, 2);

const encodeOnion = (publicKey: Uint8Array) =>
    `${encodeBase32(concat(publicKey, onionChecksum(publicKey), [ONION_VERSION])).toLowerCase()}.onion`;

function decodeOnion(text: string): EcosystemKey {
    const host = text
        .replace(/^[a-z]+:\/\//i, '')
        .replace(/[/:].*$/, '')
        .replace(/\.onion$/i, '')
        .split('.')
        .pop()!; // sub.domain.<address>.onion
    const bytes = CODECS.base32.decode(host);
    if (bytes?.length !== 35) throw new EcosystemError('a v3 onion address has 56 characters (older v2 addresses are not Ed25519 keys).');
    if (bytes[34] !== ONION_VERSION) throw new EcosystemError('this is not a v3 onion address.');
    const publicKey = bytes.slice(0, 32);
    if (!same(onionChecksum(publicKey), bytes.slice(32, 34)))
        throw new EcosystemError('the onion address has a wrong checksum (is a character mistyped?).');
    return { format: 'onion', publicKey };
}

/* ---------------------------------------------------------------------- NEAR */

// `ed25519:` + base58; a public key is the 32 bytes, a secret key is the seed followed by the public key (64 bytes)
const encodeNearPublic = (publicKey: Uint8Array) => `ed25519:${CODECS.base58.encode(publicKey)}`;
const encodeNearPrivate = (seed: Uint8Array, publicKey: Uint8Array) => `ed25519:${CODECS.base58.encode(concat(seed, publicKey))}`;

function decodeNear(text: string): EcosystemKey {
    const bytes = CODECS.base58.decode(text.slice('ed25519:'.length));
    if (!bytes) throw new EcosystemError('the NEAR key is not valid base58.');
    if (bytes.length === 32) return { format: 'near', publicKey: bytes };
    if (bytes.length === 64) return { format: 'near', privateKey: bytes.slice(0, 32), publicKey: bytes.slice(32) };
    throw new EcosystemError(`the NEAR key holds ${bytes.length} bytes, expected 32 (public) or 64 (secret).`);
}

/* ------------------------------------------------------------------- reading */

const PATTERNS: [EcosystemFormat, RegExp][] = [
    ['didkey', /^did:key:/i],
    ['near', /^ed25519:/],
    ['stellar', /^[GS][A-Z2-7]{55}$/],
    ['onion', /^((https?|ws):\/\/)?([a-z2-7]+\.)*[a-z2-7]{56}\.onion\b/i],
];

/** Which ecosystem a text is written in, or null: these start (did:key, ed25519:) or end (.onion) with something unmistakable. */
export function detectEcosystem(text: string): EcosystemFormat | null {
    const t = text.trim();
    return PATTERNS.find(([, pattern]) => pattern.test(t))?.[0] ?? null;
}

export function parseEcosystemKey(text: string): EcosystemKey {
    const t = text.trim();
    switch (detectEcosystem(t)) {
        case 'didkey':
            return decodeDidKey(t);
        case 'near':
            return decodeNear(t);
        case 'stellar':
            return decodeStellar(t);
        case 'onion':
            return decodeOnion(t);
        default:
            throw new EcosystemError('not a key of these formats.');
    }
}

/* ------------------------------------------------------------------- writing */

export function encodeEcosystemPublic(publicKey: Uint8Array, format: EcosystemFormat): string {
    switch (format) {
        case 'didkey':
            return encodeDidKey(publicKey);
        case 'stellar':
            return strkey(STELLAR_VERSION.public, publicKey);
        case 'onion':
            return encodeOnion(publicKey);
        case 'near':
            return encodeNearPublic(publicKey);
        default:
            throw new EcosystemError(`${ECOSYSTEM_LABELS[format]} has no public key format.`);
    }
}

export function encodeEcosystemPrivate(seed: Uint8Array, publicKey: Uint8Array, format: EcosystemFormat): string {
    switch (format) {
        case 'stellar':
            return strkey(STELLAR_VERSION.private, seed);
        case 'near':
            return encodeNearPrivate(seed, publicKey);
        case 'solana':
            return CODECS.bytes.encode(concat(seed, publicKey));
        default:
            throw new EcosystemError(`${ECOSYSTEM_LABELS[format]} has no private key format.`);
    }
}
