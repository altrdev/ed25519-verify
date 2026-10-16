import * as ed from '@noble/ed25519';
import { bytesToBase64, bytesToHex, parseBase64, parseHex } from './bytes';
import { MessageFormat, SignEncoding } from './enum';
import { isStructuredKey, KeyFormatError, parseStructuredKey } from './keyformats';

export type Field = 'publicKey' | 'privateKey' | 'signature' | 'message';
export type FieldErrors = Partial<Record<Field, string>>;

/**
 * Outcome of a verification of well formed input.
 * `permissive-only`: rejected by the strict RFC 8032 rules but accepted under ZIP215.
 */
export type Verdict = 'valid' | 'invalid' | 'permissive-only';

/** Malformed input (as opposed to a signature that is well formed but does not match). */
export class InputError extends Error {
    field: Field;

    constructor(field: Field, message: string) {
        super(message);
        this.name = 'InputError';
        this.field = field;
    }
}

const LABELS: Record<Field, string> = {
    message: 'Message',
    publicKey: 'Public key',
    privateKey: 'Private key',
    signature: 'Signature',
};

const LENGTHS: Record<Exclude<Field, 'message'>, number[]> = {
    publicKey: [32],
    signature: [64],
    // 64 bytes is the NaCl/libsodium form (32-byte seed followed by the public key)
    privateKey: [32, 64],
};

const EXPECTED: Record<Exclude<Field, 'message'>, string> = {
    publicKey: '32 bytes',
    signature: '64 bytes',
    privateKey: '32 bytes (or 64 in NaCl format)',
};

/** How a result is written: the only place where the Hex / Base64 choice still matters. */
export const encodeBytes = (bytes: Uint8Array, encoding: SignEncoding): string =>
    encoding === SignEncoding.Hex ? bytesToHex(bytes) : bytesToBase64(bytes);

/** A key pasted as PEM, OpenSSH or JWK carries its own format. */
function decodeStructuredKey(field: 'publicKey' | 'privateKey', text: string): Uint8Array {
    const label = LABELS[field];
    let key;
    try {
        key = parseStructuredKey(text);
    } catch (error) {
        if (error instanceof KeyFormatError) throw new InputError(field, `${label}: ${error.message}`);
        throw error;
    }
    if (field === 'privateKey') {
        if (!key.privateKey) throw new InputError(field, `${label}: this is a public key (${key.format}), the private key goes here.`);
        return key.privateKey;
    }
    if (!key.publicKey) {
        throw new InputError(field, `${label}: this is a private key (${key.format}) that does not include its public part: paste the public key instead, or use the Sign tab.`);
    }
    return key.publicKey;
}

/**
 * Decodes a key or signature written in hex or in base64, throwing an InputError that says what is wrong with it.
 *
 * The encoding is not asked for, the text tells. A valid size in hex is 64 or 128 characters, in base64 43, 44, 86 or 88,
 * so a text cannot be valid under both readings. A text made of hex digits only is read as hex, even when it would also
 * decode as base64 of another size: that is a truncated hex key (a real base64 key is never made of hex digits only), and
 * it deserves "expected 32 bytes, got 21" rather than being taken for a different key.
 */
function decodeField(field: Exclude<Field, 'message'>, raw: string | null | undefined): Uint8Array {
    const label = LABELS[field];
    if (!(raw ?? '').trim()) throw new InputError(field, `${label} is required.`);
    if (field !== 'signature' && isStructuredKey(raw!)) return decodeStructuredKey(field, raw!);

    // tolerate line breaks and spaces coming from a paste
    const value = raw!.replace(/\s+/g, '');
    const expected = `${label}: expected ${EXPECTED[field]}`;

    if (/^[0-9a-f]+$/i.test(value)) {
        const bytes = parseHex(value);
        if (!bytes) throw new InputError(field, `${label} is not valid hex: it has an odd number of digits (${value.length}).`);
        if (!LENGTHS[field].includes(bytes.length)) throw new InputError(field, `${expected}, got ${bytes.length} (read as hex).`);
        return bytes;
    }

    const bytes = parseBase64(value);
    if (!bytes) throw new InputError(field, `${label} is not valid hex or base64.`);
    if (!LENGTHS[field].includes(bytes.length)) throw new InputError(field, `${expected}, got ${bytes.length} (read as base64).`);
    return bytes;
}

/** The bytes of the message, which can be plain text (UTF-8) or already encoded as hex / base64. */
function decodeMessage(raw: string | null | undefined, format: MessageFormat): Uint8Array {
    const text = raw ?? '';
    if (format === MessageFormat.Text) return new TextEncoder().encode(text);

    // an empty message is a valid message; whitespace from a paste is tolerated
    const value = text.replace(/\s+/g, '');
    if (!value) return new Uint8Array(0);

    const bytes = format === MessageFormat.Hex ? parseHex(value) : parseBase64(value);
    if (!bytes) throw new InputError('message', `Message is not valid ${format === MessageFormat.Hex ? 'hex' : 'base64'}.`);
    return bytes;
}

/** The seed of a private key, whether it was given as 32 bytes or in the 64-byte NaCl form. */
const seedOf = (key: Uint8Array): Uint8Array => key.slice(0, 32);

export async function generateKeyPair(encoding: SignEncoding): Promise<{ privateKey: string; publicKey: string }> {
    const { secretKey, publicKey } = await ed.keygenAsync();
    return { privateKey: encodeBytes(secretKey, encoding), publicKey: encodeBytes(publicKey, encoding) };
}

class VerifyEd25519 {
    message: string;
    signature: string | null;
    publicKey: string | null;
    privateKey: string | null;
    messageFormat: MessageFormat;

    constructor(
        message: string,
        signature: string | null,
        publicKey: string | null,
        privateKey: string | null,
        messageFormat: MessageFormat = MessageFormat.Text,
    ) {
        this.message = message;
        this.messageFormat = messageFormat;
        this.signature = signature;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /** Checks the given fields and returns a message for each one that is malformed. */
    validate(fields: Field[]): FieldErrors {
        const errors: FieldErrors = {};
        for (const field of fields) {
            try {
                if (field === 'message') decodeMessage(this.message, this.messageFormat);
                else decodeField(field, this[field]);
            } catch (error) {
                if (!(error instanceof InputError)) throw error;
                errors[field] = error.message;
            }
        }
        return errors;
    }

    /** Resolves to false for a wrong signature; rejects with an InputError for malformed input. */
    async check(): Promise<boolean> {
        return (await this.verdict()) === 'valid';
    }

    /**
     * Like check(), but tells apart a signature that is only accepted by the permissive ZIP215 rules.
     * Only the strict RFC 8032 / FIPS 186-5 rules make a signature 'valid' (noble defaults to ZIP215).
     */
    async verdict(): Promise<Verdict> {
        const signature = decodeField('signature', this.signature);
        const publicKey = decodeField('publicKey', this.publicKey);
        const message = decodeMessage(this.message, this.messageFormat);

        const verifies = async (zip215: boolean) => {
            try {
                return await ed.verifyAsync(signature, message, publicKey, { zip215 });
            } catch {
                // well formed but not usable (e.g. a public key that is not a point on the curve)
                return false;
            }
        };

        if (await verifies(false)) return 'valid';
        return (await verifies(true)) ? 'permissive-only' : 'invalid';
    }

    /** The signature as raw bytes; sign() writes it in the encoding of your choice. */
    async signBytes(): Promise<Uint8Array> {
        const seed = seedOf(decodeField('privateKey', this.privateKey));
        const message = decodeMessage(this.message, this.messageFormat);
        return ed.signAsync(message, seed);
    }

    async sign(encoding: SignEncoding): Promise<string> {
        return encodeBytes(await this.signBytes(), encoding);
    }

    /** The public key of the private key, as raw bytes. */
    async getPublicKeyBytes(): Promise<Uint8Array> {
        return ed.getPublicKeyAsync(seedOf(decodeField('privateKey', this.privateKey)));
    }

    async getPublicKey(encoding: SignEncoding): Promise<string> {
        return encodeBytes(await this.getPublicKeyBytes(), encoding);
    }
}

export default VerifyEd25519;
