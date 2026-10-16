/**
 * Writes a key as a key file: PEM (PKCS#8 / SubjectPublicKeyInfo), OpenSSH or JWK. The counterpart of keyformats.ts, which reads
 * them. What is written here must be read by other tools (OpenSSL, ssh, JOSE libraries), not only by keyformats.ts: the tests
 * compare it with files made by OpenSSL and Python, and it was loaded with them (see the pull request).
 */
import { bytesToBase64 } from './bytes';
import { CODECS, encodeAs } from './codecs';
import { ECOSYSTEM_FORMATS, ECOSYSTEM_LABELS, encodeEcosystemPrivate, encodeEcosystemPublic } from './ecosystems';
import type { EcosystemFormat, FieldFormat, KeyFileFormat, RawFormat } from './enum';

/** Key files (PEM, OpenSSH, JWK) and the formats of the ecosystems (did:key, Stellar...): anything that is not a plain notation. */
export const FILE_FORMATS: KeyFileFormat[] = ['pem', 'openssh', 'jwk'];
export const KEY_FILE_FORMATS: KeyFileFormat[] = [...FILE_FORMATS, ...ECOSYSTEM_FORMATS];
export const isKeyFile = (format: FieldFormat): format is KeyFileFormat => (KEY_FILE_FORMATS as string[]).includes(format);

export const KEY_FILE_LABELS: Record<KeyFileFormat, string> = { pem: 'PEM', openssh: 'OpenSSH', jwk: 'JWK', ...ECOSYSTEM_LABELS };

/** Which format a name given by keyformats.ts ("PEM (PKCS#8)", "OpenSSH public key", "JWK", "Stellar"...) is. */
export function keyFileOf(structured: string): KeyFileFormat {
    if (structured.startsWith('PEM')) return 'pem';
    if (structured.startsWith('OpenSSH')) return 'openssh';
    const ecosystem = ECOSYSTEM_FORMATS.find((format) => ECOSYSTEM_LABELS[format] === structured);
    return ecosystem ?? 'jwk';
}

const isEcosystem = (format: FieldFormat): format is EcosystemFormat => (ECOSYSTEM_FORMATS as string[]).includes(format);

export const labelOf = (format: FieldFormat): string => (isKeyFile(format) ? KEY_FILE_LABELS[format] : CODECS[format].label);

const concat = (...parts: Uint8Array[]): Uint8Array => {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
};

const hexToBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));

// DER headers: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING (32 bytes) } } and
// SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (33 bytes, 0 unused bits) }. Fixed lengths: an Ed25519 key is always 32 bytes.
const PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420');
const SPKI_PREFIX = hexToBytes('302a300506032b6570032100');

/** PEM armor: base64 of the DER, wrapped at `width` characters, with the BEGIN / END lines and a final newline. */
function pem(label: string, der: Uint8Array, width = 64): string {
    const lines = bytesToBase64(der).match(new RegExp(`.{1,${width}}`, 'g')) ?? [];
    return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`, ''].join('\n');
}

/* ------------------------------------------------------------ SSH wire format */

const u32 = (value: number) => Uint8Array.from([value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255]);
const sshString = (bytes: Uint8Array) => concat(u32(bytes.length), bytes);
const ascii = (text: string) => new TextEncoder().encode(text);

const sshPublicBlob = (publicKey: Uint8Array) => concat(sshString(ascii('ssh-ed25519')), sshString(publicKey));

/** `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…`, the line of authorized_keys and of id_ed25519.pub (without a comment). */
export const encodeOpenSshPublic = (publicKey: Uint8Array): string => `ssh-ed25519 ${bytesToBase64(sshPublicBlob(publicKey))}`;

/**
 * An unencrypted `BEGIN OPENSSH PRIVATE KEY` file (PROTOCOL.key in the OpenSSH sources). The two "check" integers only have to
 * be equal: they are taken from the public key so that the same key always gives the same file.
 */
export function encodeOpenSshPrivate(seed: Uint8Array, publicKey: Uint8Array): string {
    const check = u32(((publicKey[0] << 24) | (publicKey[1] << 16) | (publicKey[2] << 8) | publicKey[3]) >>> 0);
    let section = concat(
        check, check,
        sshString(ascii('ssh-ed25519')),
        sshString(publicKey),
        sshString(concat(seed, publicKey)),    // OpenSSH keeps the seed followed by the public key
        sshString(new Uint8Array(0)),          // comment
    );
    // padded to the cipher block size (8 for "none") with 1, 2, 3...
    const padding = (8 - (section.length % 8)) % 8;
    section = concat(section, Uint8Array.from({ length: padding }, (_, i) => i + 1));

    const body = concat(
        ascii('openssh-key-v1\0'),
        sshString(ascii('none')), sshString(ascii('none')), sshString(new Uint8Array(0)),    // cipher, kdf, kdf options
        u32(1),                                                                              // one key
        sshString(sshPublicBlob(publicKey)),
        sshString(section),
    );
    return pem('OPENSSH PRIVATE KEY', body, 70);
}

/* ------------------------------------------------------------------------ JWK */

/** RFC 8037: `{"kty":"OKP","crv":"Ed25519","d":…,"x":…}`; the public one has no "d". Base64url without padding. */
export function encodeJwk(publicKey: Uint8Array, seed?: Uint8Array): string {
    const b64url = CODECS.base64url.encode;
    const jwk: Record<string, string> = { kty: 'OKP', crv: 'Ed25519' };
    if (seed) jwk.d = b64url(seed);
    jwk.x = b64url(publicKey);
    return JSON.stringify(jwk, null, 2);
}

/* ------------------------------------------------------------------- entry points */

export function encodePublicKey(publicKey: Uint8Array, format: FieldFormat): string {
    switch (format) {
        case 'pem': return pem('PUBLIC KEY', concat(SPKI_PREFIX, publicKey));
        case 'openssh': return encodeOpenSshPublic(publicKey);
        case 'jwk': return encodeJwk(publicKey);
        default: return isEcosystem(format) ? encodeEcosystemPublic(publicKey, format) : encodeAs(publicKey, format as RawFormat);
    }
}

/** `seed` is the 32-byte private key; the public key is needed by OpenSSH and JWK files. */
export function encodePrivateKey(seed: Uint8Array, publicKey: Uint8Array, format: FieldFormat): string {
    switch (format) {
        case 'pem': return pem('PRIVATE KEY', concat(PKCS8_PREFIX, seed));
        case 'openssh': return encodeOpenSshPrivate(seed, publicKey);
        case 'jwk': return encodeJwk(publicKey, seed);
        default: return isEcosystem(format) ? encodeEcosystemPrivate(seed, publicKey, format) : encodeAs(seed, format as RawFormat);
    }
}
