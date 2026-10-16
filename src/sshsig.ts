/**
 * SSH signatures (SSHSIG, `ssh-keygen -Y sign`, PROTOCOL.sshsig of OpenSSH): an armored file
 *
 *     -----BEGIN SSH SIGNATURE-----  base64 of  "SSHSIG" | version 1 | public key | namespace | reserved | hash algorithm | signature
 *
 * The signature is NOT over the message: it is over a small structure that holds the namespace, the hash algorithm and the hash of
 * the message (`SSHSIG | namespace | reserved | hash algorithm | H(message)`). The namespace says what the signature is for ("file",
 * "git", "email"...), so that a signature made for one purpose is not taken for another. The public key travels inside the
 * signature: the key you trust is the one you give, and it must be the one inside.
 * Pure functions: the screen is in SshsigPanel.tsx.
 */
import * as ed from '@noble/ed25519';
import { bytesToBase64, parseBase64 } from './bytes';

export class SshsigError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SshsigError';
    }
}

export type HashAlgorithm = 'sha256' | 'sha512';
export const HASH_ALGORITHMS: HashAlgorithm[] = ['sha256', 'sha512'];

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });
const MAGIC = encoder.encode('SSHSIG');

const concat = (...parts: Uint8Array[]): Uint8Array => {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
};
const u32 = (value: number) => Uint8Array.from([value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255]);
const sshString = (bytes: Uint8Array | string) => {
    const data = typeof bytes === 'string' ? encoder.encode(bytes) : bytes;
    return concat(u32(data.length), data);
};

class Reader {
    private pos = 0;
    constructor(private readonly buf: Uint8Array) {}
    bytes(length: number): Uint8Array {
        if (this.pos + length > this.buf.length) throw new SshsigError('The signature is cut short: it is not a complete SSH signature.');
        const value = this.buf.slice(this.pos, this.pos + length);
        this.pos += length;
        return value;
    }
    u32(): number {
        const b = this.bytes(4);
        return b[0] * 2 ** 24 + (b[1] << 16) + (b[2] << 8) + b[3];
    }
    string(): Uint8Array {
        return this.bytes(this.u32());
    }
    get done() {
        return this.pos === this.buf.length;
    }
}

export interface ParsedSshsig {
    /** the Ed25519 public key inside the signature (32 bytes) */
    publicKey: Uint8Array;
    namespace: string;
    reserved: Uint8Array;
    hashAlgorithm: HashAlgorithm;
    /** 64 bytes */
    signature: Uint8Array;
}

const BEGIN = '-----BEGIN SSH SIGNATURE-----';
const END = '-----END SSH SIGNATURE-----';

/** Reads an armored SSH signature. A line may have leading spaces (a signature copied out of a git commit). */
export function parseSshsig(text: string): ParsedSshsig {
    const lines = text
        .trim()
        .split(/\r?\n/)
        .map((line) => line.trim());
    if (lines.length < 3 || lines[0] !== BEGIN || lines[lines.length - 1] !== END) {
        throw new SshsigError(`An SSH signature starts with "${BEGIN}" and ends with "${END}".`);
    }
    const data = parseBase64(lines.slice(1, -1).join(''));
    if (!data) throw new SshsigError('The body of the signature is not valid base64.');

    const reader = new Reader(data);
    if (!sameBytes(reader.bytes(6), MAGIC)) throw new SshsigError('This is not an SSH signature (the "SSHSIG" marker is missing).');
    const version = reader.u32();
    if (version !== 1) throw new SshsigError(`This SSH signature has version ${version}, only version 1 is known.`);

    const keyBlob = new Reader(reader.string());
    const keyType = decoder.decode(keyBlob.string());
    if (keyType !== 'ssh-ed25519') {
        throw new SshsigError(
            keyType === 'sk-ssh-ed25519@openssh.com'
                ? 'This signature was made with a security-key (FIDO) key, which signs differently: only plain ssh-ed25519 keys are supported.'
                : `This signature was made with a "${keyType.slice(0, 30)}" key, only ssh-ed25519 is supported.`,
        );
    }
    const publicKey = keyBlob.string();
    if (publicKey.length !== 32)
        throw new SshsigError(`The public key inside the signature has ${publicKey.length} bytes, an Ed25519 key has 32.`);

    const namespace = decoder.decode(reader.string());
    const reserved = reader.string();
    const hashAlgorithm = decoder.decode(reader.string());
    if (hashAlgorithm !== 'sha256' && hashAlgorithm !== 'sha512') {
        throw new SshsigError(`The signature uses the hash "${hashAlgorithm.slice(0, 30)}": only sha256 and sha512 are supported.`);
    }

    const signatureBlob = new Reader(reader.string());
    const signatureType = decoder.decode(signatureBlob.string());
    if (signatureType !== 'ssh-ed25519')
        throw new SshsigError(`The signature itself is of type "${signatureType.slice(0, 30)}", not ssh-ed25519.`);
    const signature = signatureBlob.string();
    if (signature.length !== 64) throw new SshsigError(`The signature has ${signature.length} bytes, an Ed25519 signature has 64.`);
    if (!reader.done) throw new SshsigError('There is unexpected data after the signature.');

    return { publicKey, namespace, reserved, hashAlgorithm, signature };
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, i) => value === b[i]);

export const hashOf = async (algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await crypto.subtle.digest(algorithm === 'sha256' ? 'SHA-256' : 'SHA-512', data as BufferSource));

/** What is really signed: `SSHSIG | namespace | reserved | hash algorithm | H(message)`. */
export async function signedData(
    message: Uint8Array,
    parts: { namespace: string; reserved?: Uint8Array; hashAlgorithm: HashAlgorithm },
): Promise<Uint8Array> {
    return concat(
        MAGIC,
        sshString(parts.namespace),
        sshString(parts.reserved ?? new Uint8Array(0)),
        sshString(parts.hashAlgorithm),
        sshString(await hashOf(parts.hashAlgorithm, message)),
    );
}

/** The structure a given parsed signature is checked against for a message: for the verification and for the hints. */
export const signedDataOf = (parsed: ParsedSshsig, message: Uint8Array) => signedData(message, parsed);

/** `SHA256:…`, the fingerprint that ssh-keygen -l and the SSH tools show for a key. */
export async function fingerprint(publicKey: Uint8Array): Promise<string> {
    const blob = concat(sshString('ssh-ed25519'), sshString(publicKey));
    const digest = await hashOf('sha256', blob);
    return `SHA256:${bytesToBase64(digest).replace(/=+$/, '')}`;
}

/** The armored signature of a signature (64 bytes) made over `signedData`. Lines of 70 characters, as ssh-keygen writes them. */
export function encodeSshsig(parts: {
    publicKey: Uint8Array;
    namespace: string;
    hashAlgorithm: HashAlgorithm;
    signature: Uint8Array;
}): string {
    const blob = concat(
        MAGIC,
        u32(1),
        sshString(concat(sshString('ssh-ed25519'), sshString(parts.publicKey))),
        sshString(parts.namespace),
        sshString(new Uint8Array(0)),
        sshString(parts.hashAlgorithm),
        sshString(concat(sshString('ssh-ed25519'), sshString(parts.signature))),
    );
    const lines = bytesToBase64(blob).match(/.{1,70}/g) ?? [];
    return [BEGIN, ...lines, END, ''].join('\n');
}

/** Signs a message the way `ssh-keygen -Y sign` does. */
export async function signSshsig(
    message: Uint8Array,
    seed: Uint8Array,
    options: { namespace: string; hashAlgorithm: HashAlgorithm },
): Promise<{ armored: string; publicKey: Uint8Array }> {
    const publicKey = await ed.getPublicKeyAsync(seed);
    const signature = await ed.signAsync(await signedData(message, options), seed);
    return { armored: encodeSshsig({ publicKey, ...options, signature }), publicKey };
}

/** What the namespace field must hold: ssh-keygen refuses an empty one and one with a space or a comma. */
export function checkNamespace(namespace: string): void {
    if (!namespace) throw new SshsigError('A namespace is required: it says what the signature is for (file, git, email...).');
    if (/[\s,]/.test(namespace)) throw new SshsigError('A namespace cannot contain spaces or commas.');
}
