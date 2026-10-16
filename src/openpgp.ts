/**
 * OpenPGP (RFC 4880, RFC 9580) signatures made with Ed25519, verification only. A signature is a packet with the type of what is
 * signed, the algorithm and hash, "subpackets" (the time, the key that made it) and the signature; it is NOT over the message but
 * over the hash of `message | the signature's own header | a trailer`, and the Ed25519 signature is made over that hash.
 * Also reads the armor (`-----BEGIN PGP …-----` with its CRC-24), cleartext signed messages and public keys (primary key and
 * subkeys, their fingerprints). It does NOT judge a key: certification, expiry and revocation are not checked, only the mathematics.
 * Pure functions: the screen is in PgpPanel.tsx.
 */
import { bytesToHex, parseBase64 } from './bytes';
import { sha3_256 } from './sha3';

export class PgpError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'PgpError';
    }
}

const decoder = new TextDecoder('utf-8', { fatal: false });
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
const u16 = (value: number) => Uint8Array.of(value >> 8, value & 255);
const u32 = (value: number) => Uint8Array.of((value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
const readU32 = (b: Uint8Array, at = 0) => b[at] * 2 ** 24 + (b[at + 1] << 16) + (b[at + 2] << 8) + b[at + 3];
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, i) => value === b[i]);

// ---- armor -------------------------------------------------------------------------------------------------------------------

/** CRC-24 of the armor (RFC 4880 section 6.1). */
export function crc24(data: Uint8Array): number {
    let crc = 0xb704ce;
    for (const byte of data) {
        crc ^= byte << 16;
        for (let i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000) crc ^= 0x864cfb;
        }
    }
    return crc & 0xffffff;
}

export type ArmorKind = 'signature' | 'public key' | 'message';

export interface Armored {
    kind: ArmorKind;
    bytes: Uint8Array;
}

const BEGIN = /^-----BEGIN PGP ([A-Z ]+)-----$/;

const kindOf = (label: string): ArmorKind => {
    if (label === 'SIGNATURE') return 'signature';
    if (label === 'PUBLIC KEY BLOCK') return 'public key';
    if (label === 'MESSAGE') return 'message';
    if (label === 'PRIVATE KEY BLOCK') {
        throw new PgpError('This is a PRIVATE key block. Paste the public key only: a private key does not belong in a web page.');
    }
    throw new PgpError(`"PGP ${label}" is not something this page reads (a signature or a public key).`);
};

/** The bytes inside an armor block, starting at the line `start` of `lines`: the header lines, a blank line, the base64, the checksum. */
function readArmor(lines: string[], start: number): { armored: Armored; next: number } {
    const match = BEGIN.exec(lines[start]);
    if (!match) throw new PgpError('Armor starts with a line "-----BEGIN PGP …-----".');
    const kind = kindOf(match[1]);
    let i = start + 1;
    while (i < lines.length && lines[i].trim() !== '') i++; // the "Version:" style headers, up to the blank line
    i++;
    let body = '';
    let checksum: string | null = null;
    for (; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line === `-----END PGP ${match[1]}-----`) {
            const bytes = parseBase64(body);
            if (!bytes || bytes.length === 0) throw new PgpError('The body of the armor is not valid base64.');
            if (checksum !== null) {
                const expected = parseBase64(checksum);
                if (expected?.length !== 3) throw new PgpError('The checksum line of the armor (=XXXX) is not valid.');
                if (crc24(bytes) !== (expected[0] << 16) + (expected[1] << 8) + expected[2]) {
                    throw new PgpError('The checksum of the armor does not match: the text was altered or cut, a character is missing.');
                }
            }
            return { armored: { kind, bytes }, next: i + 1 };
        }
        if (line.startsWith('=') && line.length === 5) checksum = line.slice(1);
        else if (line.startsWith('-----')) break;
        else body += line;
    }
    throw new PgpError(`The armor has no "-----END PGP ${match[1]}-----" line: the text is cut short.`);
}

export interface Cleartext {
    /** the text that is signed, in its canonical form (lines end with CR LF, no trailing spaces) */
    text: string;
    signature: Uint8Array;
    /** the "Hash:" lines */
    hashes: string[];
}

const CLEAR_BEGIN = '-----BEGIN PGP SIGNED MESSAGE-----';

/** A cleartext signed message: the text, readable as is, then its signature. Dash-escaped lines are restored. */
export function parseCleartext(text: string): Cleartext {
    const lines = text.trim().split(/\r?\n/);
    if (lines[0].trim() !== CLEAR_BEGIN) throw new PgpError('A cleartext signed message starts with "-----BEGIN PGP SIGNED MESSAGE-----".');
    let i = 1;
    const hashes: string[] = [];
    while (i < lines.length && lines[i].trim() !== '') {
        const header = /^Hash:\s*(.*)$/.exec(lines[i]);
        if (header) hashes.push(...header[1].split(',').map((name) => name.trim()));
        i++;
    }
    i++;
    const body: string[] = [];
    for (
        ;
        i < lines.length && lines[i] !== '-----BEGIN PGP SIGNATURE-----' && lines[i].trimEnd() !== '-----BEGIN PGP SIGNATURE-----';
        i++
    ) {
        body.push(lines[i].startsWith('- ') ? lines[i].slice(2) : lines[i]);
    }
    if (i >= lines.length) throw new PgpError('The cleartext message has no "-----BEGIN PGP SIGNATURE-----" block after its text.');
    const { armored } = readArmor(
        lines.map((line) => line.trimEnd()),
        i,
    );
    if (armored.kind !== 'signature') throw new PgpError('The block after the text is not a signature.');
    // the line break before the signature belongs to the armor, not to the text; trailing spaces and tabs are not signed
    return { text: body.map((line) => line.replace(/[ \t]+$/, '')).join('\r\n'), signature: armored.bytes, hashes };
}

export const isCleartext = (text: string) => text.trimStart().startsWith(CLEAR_BEGIN);

/** Armor, a cleartext message, or bytes written as hex / base64 (a binary `.sig` or `.gpg` file). */
export function readPgp(text: string): { armored: Armored } | { cleartext: Cleartext } {
    if (isCleartext(text)) return { cleartext: parseCleartext(text) };
    const trimmed = text.trim();
    if (trimmed.startsWith('-----BEGIN'))
        return {
            armored: readArmor(
                trimmed.split(/\r?\n/).map((line) => line.trimEnd()),
                0,
            ).armored,
        };
    const compact = trimmed.replace(/\s+/g, '').replace(/^0x/i, '');
    const bytes =
        /^[0-9a-f]+$/i.test(compact) && compact.length % 2 === 0
            ? Uint8Array.from(compact.match(/../g) ?? [], (h) => parseInt(h, 16))
            : parseBase64(compact);
    if (!bytes || bytes.length === 0) {
        throw new PgpError(
            'Expected an armored block (-----BEGIN PGP …-----), a cleartext signed message, or the bytes of the file as hex or base64.',
        );
    }
    return { armored: { kind: 'message', bytes } };
}

// ---- packets -----------------------------------------------------------------------------------------------------------------

export interface Packet {
    tag: number;
    body: Uint8Array;
}

/** Splits the bytes into packets (old and new format headers). */
export function readPackets(data: Uint8Array): Packet[] {
    const packets: Packet[] = [];
    let pos = 0;
    const cut = () => new PgpError('The data is cut short in the middle of a packet.');
    while (pos < data.length) {
        const first = data[pos++];
        if (!(first & 0x80)) throw new PgpError('This is not OpenPGP data (a packet header does not start with a 1 bit).');
        let tag: number;
        let length: number;
        if (first & 0x40) {
            tag = first & 0x3f;
            const a = data[pos++];
            if (a === undefined) throw cut();
            if (a < 192) length = a;
            else if (a < 224) {
                if (pos >= data.length) throw cut();
                length = ((a - 192) << 8) + data[pos++] + 192;
            } else if (a === 255) {
                if (pos + 4 > data.length) throw cut();
                length = readU32(data, pos);
                pos += 4;
            } else throw new PgpError('A packet of partial length is not something a signature or a key uses.');
        } else {
            tag = (first & 0x3c) >> 2;
            const kind = first & 3;
            if (kind === 3) throw new PgpError('A packet of indeterminate length is not supported.');
            const size = [1, 2, 4][kind];
            if (pos + size > data.length) throw cut();
            length = 0;
            for (let i = 0; i < size; i++) length = length * 256 + data[pos++];
        }
        if (pos + length > data.length) throw cut();
        packets.push({ tag, body: data.slice(pos, pos + length) });
        pos += length;
    }
    return packets;
}

// ---- public keys -------------------------------------------------------------------------------------------------------------

export const ALGORITHM_EDDSA_LEGACY = 22;
export const ALGORITHM_ED25519 = 27;
const ED25519_OID = Uint8Array.of(0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01);

export interface PgpKey {
    /** 4 or 6 */
    version: number;
    /** 22 (EdDSA, the legacy form of RFC 4880bis) or 27 (Ed25519, RFC 9580) */
    algorithm: number;
    publicKey: Uint8Array;
    /** upper-case hex */
    fingerprint: string;
    keyId: string;
    created: number;
    primary: boolean;
}

export interface PgpCertificate {
    keys: PgpKey[];
    userIds: string[];
    /** keys of other algorithms, which cannot make an Ed25519 signature */
    skipped: number;
}

async function digest(name: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512', data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest(name, data as BufferSource));
}

async function readKey(body: Uint8Array, primary: boolean): Promise<PgpKey | null> {
    const version = body[0];
    if (version !== 4 && version !== 6) {
        throw new PgpError(`A key of version ${version} is not supported (4 and 6 are).`);
    }
    const created = readU32(body, 1);
    const algorithm = body[5];
    let material = body.slice(version === 6 ? 10 : 6);
    if (version === 6 && material.length !== readU32(body, 6))
        throw new PgpError('The key material of a version 6 key has the wrong length.');
    let publicKey: Uint8Array;
    if (algorithm === ALGORITHM_EDDSA_LEGACY) {
        const oidLength = material[0];
        const oid = material.slice(1, 1 + oidLength);
        if (!sameBytes(oid, ED25519_OID)) return null; // an EdDSA key on another curve
        material = material.slice(1 + oidLength);
        const bits = (material[0] << 8) + material[1];
        const point = material.slice(2, 2 + Math.ceil(bits / 8));
        if (point.length !== 33 || point[0] !== 0x40) throw new PgpError('The Ed25519 key is not a 0x40 prefix followed by 32 bytes.');
        publicKey = point.slice(1);
    } else if (algorithm === ALGORITHM_ED25519) {
        if (material.length !== 32) throw new PgpError(`An Ed25519 key has 32 bytes, this one ${material.length}.`);
        publicKey = material;
    } else {
        return null;
    }
    const full = version === 6 ? concat(Uint8Array.of(0x9b), u32(body.length), body) : concat(Uint8Array.of(0x99), u16(body.length), body);
    const hash = version === 6 ? await digest('SHA-256', full) : await digest('SHA-1', full);
    const keyId = version === 6 ? hash.slice(0, 8) : hash.slice(12);
    return {
        version,
        algorithm,
        publicKey,
        fingerprint: bytesToHex(hash).toUpperCase(),
        keyId: bytesToHex(keyId).toUpperCase(),
        created,
        primary,
    };
}

/** The Ed25519 keys of a public key block (the primary key and its subkeys), with their fingerprints and the user IDs it claims. */
export async function parseCertificate(data: Uint8Array): Promise<PgpCertificate> {
    const packets = readPackets(data);
    const result: PgpCertificate = { keys: [], userIds: [], skipped: 0 };
    for (const { tag, body } of packets) {
        if (tag === 5 || tag === 7)
            throw new PgpError('This contains a PRIVATE key. Paste the public key only: a private key does not belong in a web page.');
        if (tag === 6 || tag === 14) {
            const key = await readKey(body, tag === 6);
            if (key) result.keys.push(key);
            else result.skipped++;
        } else if (tag === 13) {
            result.userIds.push(decoder.decode(body));
        }
    }
    if (result.keys.length === 0) {
        throw new PgpError(
            result.skipped
                ? 'This public key has no Ed25519 key (it is RSA, ECDSA or another kind), which this page does not handle.'
                : 'No public key packet was found in this data.',
        );
    }
    return result;
}

// ---- signatures --------------------------------------------------------------------------------------------------------------

export const HASH_NAMES: Record<number, string> = {
    1: 'MD5',
    2: 'SHA-1',
    3: 'RIPEMD-160',
    8: 'SHA-256',
    9: 'SHA-384',
    10: 'SHA-512',
    11: 'SHA-224',
    12: 'SHA3-256',
    14: 'SHA3-512',
};

export const SIGNATURE_TYPES: Record<number, string> = {
    0: 'a binary document',
    1: 'a text document (canonical text form)',
    2: 'a standalone signature',
    16: 'a certification of a user ID',
    17: 'a certification of a user ID',
    18: 'a certification of a user ID',
    19: 'a certification of a user ID',
    24: 'a subkey binding',
    25: 'a primary key binding',
    31: 'a direct key signature',
    32: 'a key revocation',
    40: 'a subkey revocation',
    48: 'a certification revocation',
    64: 'a timestamp',
    80: 'a third-party confirmation',
};

export interface ParsedPgpSignature {
    version: 4 | 6;
    /** 0x00: binary, 0x01: text */
    type: number;
    algorithm: number;
    hash: number;
    /** the 64 bytes R | S */
    signature: Uint8Array;
    /** the first two bytes of the hash, kept by the signature to catch a wrong document quickly */
    hashPrefix: Uint8Array;
    /** version 6 only */
    salt: Uint8Array;
    /** the bytes the signature adds to the hash, before the trailer */
    header: Uint8Array;
    created?: number;
    /** seconds after `created` */
    expires?: number;
    issuerKeyId?: string;
    issuerFingerprint?: string;
}

const KNOWN_SUBPACKETS = new Set([
    2, 3, 4, 5, 6, 7, 9, 11, 12, 16, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 38, 39,
]);

function readSubpackets(area: Uint8Array, into: Partial<ParsedPgpSignature>, hashed: boolean) {
    let pos = 0;
    while (pos < area.length) {
        const first = area[pos++];
        let length: number;
        if (first < 192) length = first;
        else if (first < 255) length = ((first - 192) << 8) + area[pos++] + 192;
        else {
            length = readU32(area, pos);
            pos += 4;
        }
        if (length < 1 || pos + length > area.length) throw new PgpError('A subpacket of the signature is cut short.');
        const type = area[pos] & 0x7f;
        const critical = !!(area[pos] & 0x80);
        const data = area.slice(pos + 1, pos + length);
        pos += length;
        if (critical && !KNOWN_SUBPACKETS.has(type)) {
            throw new PgpError(
                `The signature has a critical subpacket (${type}) that this page does not know: it would not be right to call it valid.`,
            );
        }
        if (type === 2 && data.length === 4 && hashed) into.created = readU32(data);
        else if (type === 3 && data.length === 4 && hashed) into.expires = readU32(data);
        else if (type === 16 && data.length === 8 && !into.issuerKeyId) into.issuerKeyId = bytesToHex(data).toUpperCase();
        else if (type === 33 && data.length > 1 && hashed) into.issuerFingerprint = bytesToHex(data.slice(1)).toUpperCase();
    }
}

const mpi = (bytes: Uint8Array, pos: number): { value: Uint8Array; next: number } => {
    const bits = (bytes[pos] << 8) + bytes[pos + 1];
    const length = Math.ceil(bits / 8);
    if (pos + 2 + length > bytes.length) throw new PgpError('The signature is cut short.');
    return { value: bytes.slice(pos + 2, pos + 2 + length), next: pos + 2 + length };
};
const pad32 = (value: Uint8Array) => {
    if (value.length > 32) throw new PgpError('A number of the signature is longer than 32 bytes.');
    const out = new Uint8Array(32);
    out.set(value, 32 - value.length);
    return out;
};

/** Reads the signature packet of a signature (the first one found) and refuses what it cannot check, saying why. */
export function parsePgpSignature(data: Uint8Array): ParsedPgpSignature {
    const packets = readPackets(data);
    if (packets.some((p) => p.tag === 6))
        throw new PgpError('This is a public key, not a signature: paste the key in the field of the public key.');
    const packet = packets.find((p) => p.tag === 2);
    if (!packet) {
        const tags = packets.map((p) => p.tag).join(', ');
        throw new PgpError(
            `There is no signature packet in this data${tags ? ` (it holds packets ${tags}: this may be a key or an encrypted message)` : ''}.`,
        );
    }
    const b = packet.body;
    const version = b[0];
    if (version === 3) throw new PgpError('This is a version 3 signature (very old format): not supported.');
    if (version !== 4 && version !== 6) throw new PgpError(`A signature of version ${version} is not supported (4 and 6 are).`);
    const type = b[1];
    const algorithm = b[2];
    const hash = b[3];
    const wide = version === 6;
    const sizeLength = wide ? 4 : 2;
    const hashedLength = wide ? readU32(b, 4) : (b[4] << 8) + b[5];
    const hashedStart = 4 + sizeLength;
    const hashed = b.slice(hashedStart, hashedStart + hashedLength);
    let pos = hashedStart + hashedLength;
    if (pos + sizeLength > b.length || hashed.length !== hashedLength) throw new PgpError('The signature is cut short.');
    const unhashedLength = wide ? readU32(b, pos) : (b[pos] << 8) + b[pos + 1];
    pos += sizeLength;
    const unhashed = b.slice(pos, pos + unhashedLength);
    pos += unhashedLength;
    const hashPrefix = b.slice(pos, pos + 2);
    pos += 2;
    let salt = new Uint8Array(0);
    if (wide) {
        const saltLength = b[pos++];
        salt = b.slice(pos, pos + saltLength);
        pos += saltLength;
    }
    if (pos > b.length) throw new PgpError('The signature is cut short.');

    if (type !== 0x00 && type !== 0x01) {
        throw new PgpError(
            `This signature is for ${SIGNATURE_TYPES[type] ?? `something of type ${type}`}, not for a document: it cannot be checked against a message.`,
        );
    }
    let signature: Uint8Array;
    if (algorithm === ALGORITHM_EDDSA_LEGACY) {
        const r = mpi(b, pos);
        const s = mpi(b, r.next);
        signature = concat(pad32(r.value), pad32(s.value));
    } else if (algorithm === ALGORITHM_ED25519) {
        signature = b.slice(pos, pos + 64);
        if (signature.length !== 64) throw new PgpError(`An Ed25519 signature has 64 bytes, this one ${signature.length}.`);
    } else {
        const names: Record<number, string> = { 1: 'RSA', 3: 'RSA', 17: 'DSA', 19: 'ECDSA', 28: 'Ed448' };
        throw new PgpError(
            `This signature was made with ${names[algorithm] ?? `algorithm ${algorithm}`}, only Ed25519 (EdDSA) is supported.`,
        );
    }
    if (!HASH_NAMES[hash]) throw new PgpError(`The signature uses the hash algorithm ${hash}, which is not known.`);

    const header = concat(Uint8Array.of(version, type, algorithm, hash), wide ? u32(hashed.length) : u16(hashed.length), hashed);
    const parsed: ParsedPgpSignature = { version, type, algorithm, hash, signature, hashPrefix, salt, header };
    readSubpackets(hashed, parsed, true);
    readSubpackets(unhashed, parsed, false);
    return parsed;
}

/** The text of a document in the canonical form of a text signature: every line break is CR LF. */
export const canonicalText = (message: Uint8Array): Uint8Array => encoder.encode(decoder.decode(message).replace(/\r\n|\r|\n/g, '\r\n'));

/** The hash that is really signed: `salt | document | header | trailer`. Only SHA-2 and SHA3-256 are computed. */
export async function signedHash(signature: ParsedPgpSignature, document: Uint8Array): Promise<Uint8Array> {
    const data = signature.type === 0x01 ? canonicalText(document) : document;
    const trailer = concat(Uint8Array.of(signature.version, 0xff), u32(signature.header.length));
    const all = concat(signature.salt, data, signature.header, trailer);
    switch (signature.hash) {
        case 8:
            return digest('SHA-256', all);
        case 9:
            return digest('SHA-384', all);
        case 10:
            return digest('SHA-512', all);
        case 12:
            return sha3_256(all);
        case 2:
            throw new PgpError('The signature hashes with SHA-1, which is broken: it is refused.');
        case 1:
        case 3:
            throw new PgpError(`The signature hashes with ${HASH_NAMES[signature.hash]}, which is broken: it is refused.`);
        default:
            throw new PgpError(
                `The signature hashes with ${HASH_NAMES[signature.hash]}, which this page cannot compute (it does SHA-256, SHA-384, SHA-512 and SHA3-256).`,
            );
    }
}

/** The keys of a certificate that may have made a signature: the one it names, or all of them when it names none. */
export function candidateKeys(signature: ParsedPgpSignature, keys: PgpKey[]): PgpKey[] {
    const same = keys.filter((key) => key.algorithm === signature.algorithm);
    if (signature.issuerFingerprint) return same.filter((key) => key.fingerprint === signature.issuerFingerprint);
    if (signature.issuerKeyId) return same.filter((key) => key.keyId === signature.issuerKeyId);
    return same;
}

/** `338D FA4E …` */
export const spaced = (fingerprint: string) => fingerprint.replace(/(.{4})(?=.)/g, '$1 ');
