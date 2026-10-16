/**
 * Ed25519 keys as other tools write them, so they can be pasted as they are:
 *
 *  - PEM, PKCS#8 private key ("BEGIN PRIVATE KEY") and SubjectPublicKeyInfo public key ("BEGIN PUBLIC KEY"), RFC 8410
 *    (what `openssl genpkey -algorithm ed25519` and most libraries produce)
 *  - OpenSSH, `ssh-ed25519 AAAA… comment` public keys and unencrypted "BEGIN OPENSSH PRIVATE KEY" files (ssh-keygen)
 *  - JWK, `{"kty":"OKP","crv":"Ed25519","x":…,"d":…}`, RFC 8037
 *
 * Everything is parsed here, by hand, to keep the bundle small; a parser that does not understand its input must say why
 * (wrong key type, encrypted, ...) rather than fail with a generic message. This module knows nothing about the UI.
 */
import { parseBase64 } from './bytes';

export interface ParsedKey {
    /** human readable name of the format, e.g. "PEM (PKCS#8)" */
    format: string;
    /** 32-byte public key, when the input contains it */
    publicKey?: Uint8Array;
    /** 32-byte private key (the seed), when the input contains it */
    privateKey?: Uint8Array;
}

/** The text is a key in a supported container, but not a usable Ed25519 key. The message says why. */
export class KeyFormatError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'KeyFormatError';
    }
}

const malformed = () => new KeyFormatError('the key data is malformed.');
const textOf = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const shown = (value: unknown) => String(value).slice(0, 30);

/** A JSON object, as opposed to the `{0x01, 0x02}` notation of a list of bytes. */
const looksLikeJwk = (text: string) => /^\{\s*("|\})/.test(text);

/** True when the text looks like PEM, an OpenSSH public key or JSON (a JWK), rather than plain hex or base64. */
export function isStructuredKey(text: string): boolean {
    const t = text.trim();
    return t.startsWith('-----BEGIN') || looksLikeJwk(t) || /^(ssh|ecdsa|sk)-[\w@.-]+\s/.test(t);
}

/** Name of the format a pasted text appears to be in, or null for plain hex / base64. It does not validate the key. */
export function detectKeyFormat(text: string): string | null {
    const t = text.trim();
    if (looksLikeJwk(t)) return 'JWK';
    if (/^(ssh|ecdsa|sk)-[\w@.-]+\s/.test(t)) return 'OpenSSH public key';
    const pem = /^-----BEGIN ([A-Z0-9 ]+)-----/.exec(t);
    if (!pem) return null;
    switch (pem[1]) {
        case 'PRIVATE KEY': return 'PEM (PKCS#8)';
        case 'PUBLIC KEY': return 'PEM (SPKI)';
        case 'OPENSSH PRIVATE KEY': return 'OpenSSH private key';
        default: return 'PEM';
    }
}

/** Text shown under a key field once the pasted key is recognised, or undefined for plain hex / base64. */
export const keyFormatHint = (text: string): string | undefined => {
    const format = detectKeyFormat(text);
    return format ? `Detected format: ${format}` : undefined;
};

export function parseStructuredKey(text: string): ParsedKey {
    const t = text.trim();
    if (t.startsWith('-----BEGIN')) return parsePem(t);
    if (looksLikeJwk(t)) return parseJwk(t);
    return parseOpenSshPublic(t);
}

/* ---------------------------------------------------------------- PEM / DER */

function parsePem(text: string): ParsedKey {
    // only the first block counts: private and public key files are often concatenated
    const match = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
    if (!match) throw new KeyFormatError('the PEM block is incomplete (is the END line missing?).');
    const [, label, body] = match;

    if (/Proc-Type:|DEK-Info:/.test(body)) {
        throw new KeyFormatError('the key is encrypted with a passphrase, which is not supported: decrypt it first.');
    }
    const der = parseBase64(body.replace(/\s+/g, ''));
    if (!der) throw new KeyFormatError('the PEM block is not valid base64.');

    switch (label) {
        case 'PRIVATE KEY': return parsePkcs8(der);
        case 'PUBLIC KEY': return parseSpki(der);
        case 'OPENSSH PRIVATE KEY': return parseOpenSshPrivate(der);
        case 'ENCRYPTED PRIVATE KEY':
            throw new KeyFormatError('the key is encrypted with a passphrase, which is not supported: decrypt it first (openssl pkey -in key.pem -out plain.pem).');
        case 'RSA PRIVATE KEY': case 'RSA PUBLIC KEY':
            throw new KeyFormatError('this is an RSA key, only Ed25519 is supported.');
        case 'EC PRIVATE KEY':
            throw new KeyFormatError('this is an EC key, only Ed25519 is supported.');
        case 'CERTIFICATE':
            throw new KeyFormatError('this is a certificate, not a key: paste the public key.');
        default:
            throw new KeyFormatError(`this is a "${shown(label)}" PEM block, not an Ed25519 key.`);
    }
}

interface Tlv { tag: number; start: number; end: number }

/** Reads one DER element (tag, length) at `offset`. `start`..`end` is the content. */
function readTlv(buf: Uint8Array, offset: number): Tlv {
    if (offset + 2 > buf.length) throw malformed();
    const tag = buf[offset];
    let length = buf[offset + 1];
    let pos = offset + 2;
    if (length & 0x80) {
        const count = length & 0x7f;
        if (count === 0 || count > 4 || pos + count > buf.length) throw malformed();
        length = 0;
        for (let i = 0; i < count; i++) length = length * 256 + buf[pos + i];
        pos += count;
    }
    if (pos + length > buf.length) throw malformed();
    return { tag, start: pos, end: pos + length };
}

function children(buf: Uint8Array, parent: Tlv): Tlv[] {
    const found: Tlv[] = [];
    for (let pos = parent.start; pos < parent.end;) {
        const child = readTlv(buf, pos);
        if (child.end > parent.end) throw malformed();
        found.push(child);
        pos = child.end;
    }
    return found;
}

const sameBytes = (a: Uint8Array, b: number[]) => a.length === b.length && a.every((v, i) => v === b[i]);

const OID_ED25519 = [0x2b, 0x65, 0x70]; // 1.3.101.112
const OTHER_ALGORITHMS: [number[], string][] = [
    [[0x2b, 0x65, 0x6e], 'an X25519'],
    [[0x2b, 0x65, 0x71], 'an Ed448'],
    [[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01], 'an RSA'],
    [[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], 'an EC'],
];

/** The AlgorithmIdentifier must be Ed25519: say which key it is when it is not. */
function checkAlgorithm(buf: Uint8Array, algorithm: Tlv) {
    const [oid] = children(buf, algorithm);
    if (!oid || oid.tag !== 0x06) throw malformed();
    const bytes = buf.subarray(oid.start, oid.end);
    if (sameBytes(bytes, OID_ED25519)) return;
    const known = OTHER_ALGORITHMS.find(([id]) => sameBytes(bytes, id));
    throw new KeyFormatError(known ? `this is ${known[1]} key, only Ed25519 is supported.` : 'this is not an Ed25519 key.');
}

/** PrivateKeyInfo, RFC 5958 / 8410: SEQUENCE { version, SEQUENCE { OID }, OCTET STRING { OCTET STRING (seed) } [, [1] public key] } */
function parsePkcs8(der: Uint8Array): ParsedKey {
    const top = readTlv(der, 0);
    if (top.tag !== 0x30) throw malformed();
    const [version, algorithm, octets, ...rest] = children(der, top);
    if (!version || version.tag !== 0x02 || !algorithm || algorithm.tag !== 0x30 || !octets || octets.tag !== 0x04) throw malformed();
    checkAlgorithm(der, algorithm);

    const inner = readTlv(der, octets.start);
    if (inner.tag !== 0x04 || inner.end > octets.end || inner.end - inner.start !== 32) throw malformed();
    const key: ParsedKey = { format: 'PEM (PKCS#8)', privateKey: der.slice(inner.start, inner.end) };

    // version 2 keys may carry the public key as [1] IMPLICIT BIT STRING
    const publicPart = rest.find((item) => item.tag === 0x81);
    if (publicPart && publicPart.end - publicPart.start === 33 && der[publicPart.start] === 0) {
        key.publicKey = der.slice(publicPart.start + 1, publicPart.end);
    }
    return key;
}

/** SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID }, BIT STRING { 0, 32 bytes } } */
function parseSpki(der: Uint8Array): ParsedKey {
    const top = readTlv(der, 0);
    if (top.tag !== 0x30) throw malformed();
    const [algorithm, bits] = children(der, top);
    if (!algorithm || algorithm.tag !== 0x30 || !bits || bits.tag !== 0x03) throw malformed();
    checkAlgorithm(der, algorithm);
    if (bits.end - bits.start !== 33 || der[bits.start] !== 0) throw malformed();
    return { format: 'PEM (SPKI)', publicKey: der.slice(bits.start + 1, bits.end) };
}

/* ------------------------------------------------------------------ OpenSSH */

/** Sequential reader for the SSH wire format: big-endian uint32 and length-prefixed strings. */
class SshReader {
    private pos: number;

    constructor(private readonly buf: Uint8Array, pos = 0) {
        this.pos = pos;
    }

    u32(): number {
        if (this.pos + 4 > this.buf.length) throw malformed();
        const b = this.buf;
        const value = b[this.pos] * 2 ** 24 + (b[this.pos + 1] << 16) + (b[this.pos + 2] << 8) + b[this.pos + 3];
        this.pos += 4;
        return value;
    }

    string(): Uint8Array {
        const length = this.u32();
        if (this.pos + length > this.buf.length) throw malformed();
        const value = this.buf.slice(this.pos, this.pos + length);
        this.pos += length;
        return value;
    }
}

const notEd25519 = (type: string) => {
    if (type === 'sk-ssh-ed25519@openssh.com') {
        return new KeyFormatError('this is a security-key (FIDO) key, which does not use plain Ed25519 signatures.');
    }
    return new KeyFormatError(`this is a "${shown(type)}" key, only ssh-ed25519 is supported.`);
};

/** `ssh-ed25519 AAAAC3Nza… comment` */
function parseOpenSshPublic(text: string): ParsedKey {
    const [type, data] = text.split(/\s+/);
    if (type !== 'ssh-ed25519') throw notEd25519(type);
    const blob = data ? parseBase64(data) : null;
    if (!blob) throw new KeyFormatError('the OpenSSH public key data is not valid base64.');

    const reader = new SshReader(blob);
    if (textOf(reader.string()) !== 'ssh-ed25519') throw malformed();
    const publicKey = reader.string();
    if (publicKey.length !== 32) throw malformed();
    return { format: 'OpenSSH public key', publicKey };
}

/** The decoded body of a "BEGIN OPENSSH PRIVATE KEY" block (PROTOCOL.key in the OpenSSH sources). */
function parseOpenSshPrivate(der: Uint8Array): ParsedKey {
    const magic = 'openssh-key-v1\0';
    if (textOf(der.subarray(0, magic.length)) !== magic) throw malformed();

    const reader = new SshReader(der, magic.length);
    const cipher = textOf(reader.string());
    reader.string(); // kdf name
    reader.string(); // kdf options
    const count = reader.u32();
    if (cipher !== 'none') {
        throw new KeyFormatError('the key is encrypted with a passphrase, which is not supported: remove it first (ssh-keygen -p -f <key>).');
    }
    if (count !== 1) throw new KeyFormatError(`the file contains ${count} keys, only one is supported.`);
    reader.string(); // public key blob (repeated in the private section)

    const section = new SshReader(reader.string());
    if (section.u32() !== section.u32()) throw malformed(); // the two "check" integers must match
    const type = textOf(section.string());
    if (type !== 'ssh-ed25519') throw notEd25519(type);
    const publicKey = section.string();
    const secret = section.string(); // seed followed by the public key
    if (publicKey.length !== 32 || secret.length !== 64) throw malformed();
    if (!secret.slice(32).every((value, index) => value === publicKey[index])) {
        throw new KeyFormatError('the key data is inconsistent: the private part does not match the public part.');
    }
    return { format: 'OpenSSH private key', privateKey: secret.slice(0, 32), publicKey };
}

/* ---------------------------------------------------------------------- JWK */

function parseJwk(text: string): ParsedKey {
    let parsed: unknown;
    try {
        parsed = JSON.parse(text);
    } catch {
        throw new KeyFormatError('the JWK is not valid JSON.');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new KeyFormatError('the JWK must be a JSON object.');
    }
    const jwk = parsed as Record<string, unknown>;
    if (Array.isArray(jwk.keys)) throw new KeyFormatError('this is a JWK Set: paste a single key.');
    if (jwk.kty !== 'OKP') {
        throw new KeyFormatError(jwk.kty ? `this is a "${shown(jwk.kty)}" JWK, not an Ed25519 key.` : 'the JWK has no "kty" member.');
    }
    if (jwk.crv !== 'Ed25519') throw new KeyFormatError(`the JWK curve is "${shown(jwk.crv)}", not Ed25519.`);

    const member = (name: 'x' | 'd'): Uint8Array | undefined => {
        const value = jwk[name];
        if (value === undefined) return undefined;
        const bytes = typeof value === 'string' ? parseBase64(value) : null;
        if (!bytes || bytes.length !== 32) throw new KeyFormatError(`the JWK member "${name}" must be 32 bytes in base64url.`);
        return bytes;
    };
    const publicKey = member('x');
    const privateKey = member('d');
    if (!publicKey && !privateKey) throw new KeyFormatError('the JWK has neither "x" (public) nor "d" (private).');
    return { format: 'JWK', publicKey, privateKey };
}
