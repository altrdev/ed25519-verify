/**
 * Hints for a signature that does not verify. Ed25519 cannot say WHICH input is wrong (a bad key, another message and a damaged
 * signature all give "false"), so this is not a diagnosis: it states what is certain about the inputs (facts), and retries the
 * verification with the usual mistakes undone (a newline at the end, the message read as hex, a hash signed instead of the
 * message...), reporting only the retries that make it valid. A truly wrong signature gets no hint. It never changes the verdict.
 */
import * as ed from '@noble/ed25519';
import { bytesToHex, parseBase64, parseHex } from './bytes';
import { MessageFormat } from './enum';

export interface Hints {
    /** things that are certainly true about the inputs and explain the failure */
    facts: string[];
    /** ways of reading or writing the inputs that make the signature valid */
    fixes: string[];
}

export interface DiagnoseInput {
    publicKey: Uint8Array;
    signature: Uint8Array;
    /** the text of the message as typed, and how it was read */
    message: string;
    messageFormat: MessageFormat;
}

// the order of the prime subgroup: an S at or above it is a non-canonical signature
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const littleEndian = (bytes: Uint8Array) => bytes.reduceRight((total, byte) => (total << 8n) | BigInt(byte), 0n);
const utf8 = (text: string) => new TextEncoder().encode(text);
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, i) => value === b[i]);

/** What is certain about the inputs, whatever the message is. */
function facts({ publicKey, signature }: DiagnoseInput): string[] {
    const found: string[] = [];
    if (littleEndian(signature.slice(32)) >= L) {
        found.push(
            'The second half of the signature (S) is not reduced: it is not smaller than the group order. The strict RFC 8032 rules reject such a signature, whatever the message and the key; it is not a signature made by a standard signer.',
        );
    }
    try {
        ed.Point.fromBytes(signature.slice(0, 32), false);
    } catch {
        found.push('The first half of the signature (R) is not a point of the curve, so no message or key can make this signature valid.');
    }
    try {
        if (ed.Point.fromBytes(publicKey, false).isSmallOrder()) {
            found.push(
                'The public key is a point of small order, a weak key that is not produced by key generation: nothing signed with a real key looks like this.',
            );
        }
    } catch {
        found.push('The public key is not a point of the curve: it cannot be the public key of any private key.');
    }
    return found;
}

const hash = async (name: 'SHA-256' | 'SHA-512', data: Uint8Array): Promise<Uint8Array | null> => {
    try {
        return new Uint8Array(await crypto.subtle.digest(name, data as BufferSource));
    } catch {
        return null;
    }
};

interface Attempt {
    /** completes "It would be valid with ..." */
    text: string;
    message?: Uint8Array;
    publicKey?: Uint8Array;
    signature?: Uint8Array;
}

async function attempts(input: DiagnoseInput, original: Uint8Array): Promise<Attempt[]> {
    const { message, messageFormat, publicKey, signature } = input;
    const found: Attempt[] = [];
    const asText = (text: string, label: string) => found.push({ text: label, message: utf8(text) });

    if (messageFormat === MessageFormat.Text) {
        asText(`${message}\n`, 'a newline added at the end of the message');
        if (/\r?\n$/.test(message)) asText(message.replace(/\r?\n$/, ''), 'the newline at the end of the message removed');
        asText(message.replace(/\s+$/, ''), 'the spaces and line breaks at the end of the message removed');
        asText(message.trim(), 'the spaces and line breaks at both ends of the message removed');
        asText(message.replace(/\r\n/g, '\n'), 'the line breaks written as \\n instead of \\r\\n');
        asText(message.replace(/\r?\n/g, '\r\n'), 'the line breaks written as \\r\\n');
        asText(message.normalize('NFC'), 'the message normalised as Unicode NFC (composed accents)');
        asText(message.normalize('NFD'), 'the message normalised as Unicode NFD (decomposed accents)');
        const compact = message.replace(/\s+/g, '');
        const hex = parseHex(compact);
        if (compact && hex) found.push({ text: 'the message read as hex (the selector is on Text)', message: hex });
        const base64 = parseBase64(compact);
        if (compact && base64) found.push({ text: 'the message read as base64 (the selector is on Text)', message: base64 });
    } else {
        asText(message, `the message read as text (the selector is on ${messageFormat === MessageFormat.Hex ? 'Hex' : 'Base64'})`);
        const compact = message.replace(/\s+/g, '');
        const other = messageFormat === MessageFormat.Hex ? parseBase64(compact) : parseHex(compact);
        if (compact && other) {
            found.push({ text: `the message read as ${messageFormat === MessageFormat.Hex ? 'base64' : 'hex'} instead`, message: other });
        }
    }

    // a hash of the message signed instead of the message (Ed25519ph-like uses, or a tool that signs a digest)
    for (const name of ['SHA-256', 'SHA-512'] as const) {
        const digest = await hash(name, original);
        if (!digest) continue;
        found.push({ text: `the ${name} hash of the message signed instead of the message (the raw bytes of the hash)`, message: digest });
        found.push({
            text: `the ${name} hash of the message signed instead of the message (the hash written as hex text)`,
            message: utf8(bytesToHex(digest)),
        });
    }

    // the "public key" is really a private key (a seed): its public key is what the signature belongs to
    try {
        found.push({ text: '', publicKey: await ed.getPublicKeyAsync(publicKey) });
    } catch {
        // not usable as a seed
    }

    // the two halves of the signature written in the other order
    found.push({
        text: 'the two halves of the signature (R and S) swapped',
        signature: new Uint8Array([...signature.slice(32), ...signature.slice(0, 32)]),
    });
    // several edits can give the same bytes (a trim and a removed newline): report the first, the most specific
    const seen = new Set<string>();
    return found.filter((attempt) => {
        if (attempt.message && same(attempt.message, original)) return false;
        const key = [attempt.message, attempt.publicKey, attempt.signature].map((bytes) => (bytes ? bytesToHex(bytes) : '-')).join('/');
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

const verifies = async (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => {
    try {
        return await ed.verifyAsync(signature, message, publicKey, { zip215: false });
    } catch {
        return false;
    }
};

/** Hints for a signature that did not verify. Call it only after a verdict of "wrong". */
export async function diagnose(input: DiagnoseInput, original: Uint8Array): Promise<Hints> {
    const results = await Promise.all(
        (await attempts(input, original)).map(async (attempt) => ({
            attempt,
            valid: await verifies(attempt.signature ?? input.signature, attempt.message ?? original, attempt.publicKey ?? input.publicKey),
        })),
    );
    const fixes: string[] = [];
    for (const { attempt, valid } of results) {
        if (!valid) continue;
        if (attempt.publicKey) {
            fixes.push(
                `The field "Public key" holds a private key (a seed): the signature is valid for its public key, ${bytesToHex(attempt.publicKey)}. Use that one.`,
            );
        } else {
            fixes.push(`It is valid with ${attempt.text}.`);
        }
    }
    return { facts: facts(input), fixes };
}
