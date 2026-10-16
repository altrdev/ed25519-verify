import * as ed from '@noble/ed25519';
import { parseBase64, parseHex } from './bytes';
import { CODECS, encodeAs, readings } from './codecs';
import { type FieldFormat, MessageFormat, type RawFormat } from './enum';
import { isStructuredKey, KeyFormatError, parseStructuredKey } from './keyformats';
import { encodePrivateKey, encodePublicKey } from './keyfiles';

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
    /** set when the text can be read in several formats and the user has to pick one */
    choices?: RawFormat[];

    constructor(field: Field, message: string, choices?: RawFormat[]) {
        super(message);
        this.name = 'InputError';
        this.field = field;
        this.choices = choices;
    }
}

/** The format to read a field in, when the text could be read in several. */
export type FormatOverrides = Partial<Record<'publicKey' | 'privateKey' | 'signature', RawFormat>>;

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

/** How a result is written. */
export const encodeBytes = (bytes: Uint8Array, format: RawFormat): string => encodeAs(bytes, format);

const formatName = (format: RawFormat) => CODECS[format].label.toLowerCase();
const listOf = (names: string[]) =>
    names.length < 3 ? names.join(' or ') : `${names.slice(0, -1).join(', ')} or ${names[names.length - 1]}`;

/** What the text of a key or signature turned out to be: its bytes and the notation they were written in. */
export interface FieldReading {
    bytes: Uint8Array;
    /** the plain notation (hex, base58, ...), null for a key file */
    format: RawFormat | null;
    /** the key file format (PEM, OpenSSH, JWK), null for a plain notation */
    structured: string | null;
}

/** A key pasted as PEM, OpenSSH or JWK carries its own format. */
function readStructuredKey(field: 'publicKey' | 'privateKey', text: string): FieldReading {
    const label = LABELS[field];
    let key: ReturnType<typeof parseStructuredKey>;
    try {
        key = parseStructuredKey(text);
    } catch (error) {
        if (error instanceof KeyFormatError) throw new InputError(field, `${label}: ${error.message}`);
        throw error;
    }
    if (field === 'privateKey') {
        if (!key.privateKey) throw new InputError(field, `${label}: this is a public key (${key.format}), the private key goes here.`);
        return { bytes: key.privateKey, format: null, structured: key.format };
    }
    if (!key.publicKey) {
        throw new InputError(
            field,
            `${label}: this is a private key (${key.format}) that does not include its public part: paste the public key instead, or use the Sign tab.`,
        );
    }
    return { bytes: key.publicKey, format: null, structured: key.format };
}

/**
 * Reads a key or signature, throwing an InputError that says what is wrong with it. The format is not asked for, the text
 * tells (see readings() in codecs.ts): a key or signature has one of a few sizes, and in almost every case only one reading of
 * the text has such a size. When two do, the text is ambiguous and the InputError lists the formats to pick from; `forced`
 * is the pick.
 */
function readField(field: Exclude<Field, 'message'>, raw: string | null | undefined, forced?: RawFormat): FieldReading {
    const label = LABELS[field];
    if (!(raw ?? '').trim()) throw new InputError(field, `${label} is required.`);
    if (field !== 'signature' && isStructuredKey(raw!)) return readStructuredKey(field, raw!);

    const expected = `${label}: expected ${EXPECTED[field]}`;
    const fits = (bytes: Uint8Array) => LENGTHS[field].includes(bytes.length);

    if (forced) {
        const text = forced === 'bytes' ? raw! : raw!.replace(/\s+/g, '');
        const bytes = CODECS[forced].decode(text);
        if (!bytes) throw new InputError(field, `${label} is not valid ${formatName(forced)}.`);
        if (!fits(bytes)) throw new InputError(field, `${expected}, got ${bytes.length} (read as ${formatName(forced)}).`);
        return { bytes, format: forced, structured: null };
    }

    const found = readings(raw!);
    const matching = found.filter((reading) => fits(reading.bytes));
    if (matching.length === 1) return { bytes: matching[0].bytes, format: matching[0].format, structured: null };
    if (matching.length > 1) {
        const formats = matching.map((reading) => reading.format);
        throw new InputError(field, `${label}: this text could be ${listOf(formats.map(formatName))}: pick the format.`, formats);
    }

    // nothing has the right size: say what was found
    const value = raw!.replace(/\s+/g, '');
    if (found.length === 0) {
        if (/^[0-9a-f]+$/i.test(value)) {
            throw new InputError(field, `${label} is not valid hex: it has an odd number of digits (${value.length}).`);
        }
        throw new InputError(field, `${label} is not in a recognised format (hex, base64, base58, base32 or a list of bytes).`);
    }
    if (found.length === 1) {
        throw new InputError(field, `${expected}, got ${found[0].bytes.length} (read as ${formatName(found[0].format)}).`);
    }
    throw new InputError(field, `${expected}, got ${listOf(found.map((r) => `${r.bytes.length} as ${formatName(r.format)}`))}.`);
}

const decodeField = (field: Exclude<Field, 'message'>, raw: string | null | undefined, forced?: RawFormat): Uint8Array =>
    readField(field, raw, forced).bytes;

/** What a key or signature text is, or null when it is empty, malformed or ambiguous (the form shows why). */
export function inspectField(field: Exclude<Field, 'message'>, raw: string, forced?: RawFormat): FieldReading | null {
    try {
        return readField(field, raw, forced);
    } catch (error) {
        if (error instanceof InputError) return null;
        throw error;
    }
}

/** The bytes of the message, which can be plain text (UTF-8), already encoded as hex / base64, or the bytes of a file. */
function decodeMessage(raw: string | Uint8Array | null | undefined, format: MessageFormat): Uint8Array {
    // the bytes of a file chosen as the message: used as they are, whatever the format selector says
    if (raw instanceof Uint8Array) return raw;
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

export async function generateKeyPair(
    privateFormat: FieldFormat,
    publicFormat: FieldFormat = privateFormat,
): Promise<{ privateKey: string; publicKey: string }> {
    const { secretKey, publicKey } = await ed.keygenAsync();
    return { privateKey: encodePrivateKey(secretKey, publicKey, privateFormat), publicKey: encodePublicKey(publicKey, publicFormat) };
}

class VerifyEd25519 {
    message: string | Uint8Array;
    signature: string | null;
    publicKey: string | null;
    privateKey: string | null;
    messageFormat: MessageFormat;
    formats: FormatOverrides;

    constructor(
        message: string | Uint8Array,
        signature: string | null,
        publicKey: string | null,
        privateKey: string | null,
        messageFormat: MessageFormat = MessageFormat.Text,
        formats: FormatOverrides = {},
    ) {
        this.message = message;
        this.messageFormat = messageFormat;
        this.formats = formats;
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
                else decodeField(field, this[field], this.formats[field]);
            } catch (error) {
                if (!(error instanceof InputError)) throw error;
                errors[field] = error.message;
            }
        }
        return errors;
    }

    /** The bytes of a key or signature field, whatever notation it is written in. */
    bytesOf(field: 'publicKey' | 'privateKey' | 'signature'): Uint8Array {
        return decodeField(field, this[field], this.formats[field]);
    }

    /** The formats to pick from, for each of the fields whose text can be read in several. */
    choices(fields: Field[]): Partial<Record<Field, RawFormat[]>> {
        const found: Partial<Record<Field, RawFormat[]>> = {};
        for (const field of fields) {
            if (field === 'message') continue;
            try {
                decodeField(field, this[field], this.formats[field]);
            } catch (error) {
                if (error instanceof InputError && error.choices) found[field] = error.choices;
            }
        }
        return found;
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
        const signature = decodeField('signature', this.signature, this.formats.signature);
        const publicKey = decodeField('publicKey', this.publicKey, this.formats.publicKey);
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
        const seed = seedOf(decodeField('privateKey', this.privateKey, this.formats.privateKey));
        const message = decodeMessage(this.message, this.messageFormat);
        return ed.signAsync(message, seed);
    }

    async sign(encoding: RawFormat): Promise<string> {
        return encodeBytes(await this.signBytes(), encoding);
    }

    /** The public key of the private key, as raw bytes. */
    async getPublicKeyBytes(): Promise<Uint8Array> {
        return ed.getPublicKeyAsync(seedOf(decodeField('privateKey', this.privateKey, this.formats.privateKey)));
    }

    async getPublicKey(encoding: RawFormat): Promise<string> {
        return encodeBytes(await this.getPublicKeyBytes(), encoding);
    }
}

export default VerifyEd25519;
