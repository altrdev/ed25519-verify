import * as ed from 'noble-ed25519';
import { MessageFormat, SignEncoding } from './enum';

export type Field = 'publicKey' | 'privateKey' | 'signature' | 'message';
export type FieldErrors = Partial<Record<Field, string>>;

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

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
};

function parseHex(value: string): Uint8Array | null {
    return /^[0-9a-f]+$/i.test(value) && value.length % 2 === 0 ? hexToBytes(value) : null;
}

function parseBase64(value: string): Uint8Array | null {
    // accept the URL-safe alphabet and missing padding as well
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) return null;
    const body = normalized.replace(/=+$/, '');
    if (body.length % 4 === 1) return null;
    try {
        return Uint8Array.from(atob(body.padEnd(Math.ceil(body.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
    } catch {
        return null;
    }
}

const parse = (value: string, encoding: SignEncoding) =>
    encoding === SignEncoding.Hex ? parseHex(value) : parseBase64(value);

const encode = (bytes: Uint8Array, encoding: SignEncoding): string =>
    encoding === SignEncoding.Hex ? bytesToHex(bytes) : btoa(String.fromCharCode(...bytes));

const encodingName = (encoding: SignEncoding) => (encoding === SignEncoding.Hex ? 'hex' : 'base64');

/** Decodes a key or signature, throwing an InputError that says what is wrong with it. */
function decodeField(field: Exclude<Field, 'message'>, raw: string | null | undefined, encoding: SignEncoding): Uint8Array {
    const label = LABELS[field];
    // tolerate line breaks and spaces coming from a paste
    const value = (raw ?? '').replace(/\s+/g, '');
    if (!value) throw new InputError(field, `${label} is required.`);

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
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const publicKey = hexToBytes(await ed.getPublicKey(bytesToHex(seed)));
    return { privateKey: encode(seed, encoding), publicKey: encode(publicKey, encoding) };
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
        const signature = decodeField('signature', this.signature, encoding);
        const publicKey = decodeField('publicKey', this.publicKey, encoding);
        const message = decodeMessage(this.message, this.messageFormat);
        try {
            return await ed.verify(bytesToHex(signature), bytesToHex(message), bytesToHex(publicKey));
        } catch {
            // well formed but not usable (e.g. a public key that is not a point on the curve)
            return false;
        }
    }

    async sign(encoding: SignEncoding): Promise<string> {
        const seed = seedOf(decodeField('privateKey', this.privateKey, encoding));
        const message = decodeMessage(this.message, this.messageFormat);
        const signature = await ed.sign(bytesToHex(message), bytesToHex(seed));
        return encode(hexToBytes(signature), encoding);
    }

    async getPublicKey(encoding: SignEncoding): Promise<string> {
        const seed = seedOf(decodeField('privateKey', this.privateKey, encoding));
        return encode(hexToBytes(await ed.getPublicKey(bytesToHex(seed))), encoding);
    }
}

export default VerifyEd25519;
