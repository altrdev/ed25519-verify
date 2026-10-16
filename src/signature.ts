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

const parse = (value: string, encoding: SignEncoding) =>
    encoding === SignEncoding.Hex ? parseHex(value) : parseBase64(value);

const encode = (bytes: Uint8Array, encoding: SignEncoding): string =>
    encoding === SignEncoding.Hex ? bytesToHex(bytes) : bytesToBase64(bytes);

const encodingName = (encoding: SignEncoding) => (encoding === SignEncoding.Hex ? 'hex' : 'base64');

/** A key pasted as PEM, OpenSSH or JWK: whichever encoding is selected, it carries its own format. */
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

/** Decodes a key or signature, throwing an InputError that says what is wrong with it. */
function decodeField(field: Exclude<Field, 'message'>, raw: string | null | undefined, encoding: SignEncoding): Uint8Array {
    const label = LABELS[field];
    if (!(raw ?? '').trim()) throw new InputError(field, `${label} is required.`);
    if (field !== 'signature' && isStructuredKey(raw!)) return decodeStructuredKey(field, raw!);

    // tolerate line breaks and spaces coming from a paste
    const value = (raw ?? '').replace(/\s+/g, '');

    const bytes = parse(value, encoding);
    if (!bytes) throw new InputError(field, `${label} is not valid ${encodingName(encoding)}.`);

    if (!LENGTHS[field].includes(bytes.length)) {
        // the most common mistake: right data, wrong encoding selected
        const otherEncoding = encoding === SignEncoding.Hex ? SignEncoding.Base64 : SignEncoding.Hex;
        const other = parse(value, otherEncoding);
        const hint = other && LENGTHS[field].includes(other.length)
            ? ` It looks like ${encodingName(otherEncoding)}: switch the encoding.`
            : '';
        throw new InputError(field, `${label}: expected ${EXPECTED[field]}, got ${bytes.length}.${hint}`);
    }
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
    return { privateKey: encode(secretKey, encoding), publicKey: encode(publicKey, encoding) };
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
    validate(encoding: SignEncoding, fields: Field[]): FieldErrors {
        const errors: FieldErrors = {};
        for (const field of fields) {
            try {
                if (field === 'message') decodeMessage(this.message, this.messageFormat);
                else decodeField(field, this[field], encoding);
            } catch (error) {
                if (!(error instanceof InputError)) throw error;
                errors[field] = error.message;
            }
        }
        return errors;
    }

    /** Resolves to false for a wrong signature; rejects with an InputError for malformed input. */
    async check(encoding: SignEncoding): Promise<boolean> {
        return (await this.verdict(encoding)) === 'valid';
    }

    /**
     * Like check(), but tells apart a signature that is only accepted by the permissive ZIP215 rules.
     * Only the strict RFC 8032 / FIPS 186-5 rules make a signature 'valid' (noble defaults to ZIP215).
     */
    async verdict(encoding: SignEncoding): Promise<Verdict> {
        const signature = decodeField('signature', this.signature, encoding);
        const publicKey = decodeField('publicKey', this.publicKey, encoding);
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

    async sign(encoding: SignEncoding): Promise<string> {
        const seed = seedOf(decodeField('privateKey', this.privateKey, encoding));
        const message = decodeMessage(this.message, this.messageFormat);
        return encode(await ed.signAsync(message, seed), encoding);
    }

    async getPublicKey(encoding: SignEncoding): Promise<string> {
        const seed = seedOf(decodeField('privateKey', this.privateKey, encoding));
        return encode(await ed.getPublicKeyAsync(seed), encoding);
    }
}

export default VerifyEd25519;
