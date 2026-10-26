/**
 * Which container a pasted signature is, when it is one of those of the "Tokens and files" tab: a JWT, an SSH signature, a minisign or signify
 * file, an OpenPGP signature, a COSE message. Only what is certain is recognised (a marker line, a header that decodes, bytes that
 * read as the CBOR of a COSE message): a text that could be a plain Ed25519 signature is never taken for a container.
 */
import { parseBase64, parseHex } from './bytes';
import { decodeCbor, isBytes, Tagged } from './cbor';
import type { MessageFormat } from './enum';
import { decodeBase64Url } from './jws';
import { looksLikeSignify } from './signify';
import type { SharedCose, SharedMinisign, SharedPgp, SharedSignify, SharedSshsig, SharedToken } from './share';

export type Container = 'jws' | 'sshsig' | 'minisign' | 'signify' | 'cose' | 'pgp';

export const CONTAINER_NAMES: Record<Container, string> = {
    jws: 'a JWS / JWT token',
    sshsig: 'an SSH signature',
    minisign: 'a minisign signature',
    signify: 'a signify signature',
    cose: 'a COSE message',
    pgp: 'an OpenPGP signature',
};

/** The name of each container in the rail and on the button that opens it. */
export const CONTAINER_LABELS: Record<Container, string> = {
    jws: 'JWS / JWT',
    sshsig: 'SSH signature',
    minisign: 'minisign',
    signify: 'signify',
    cose: 'COSE',
    pgp: 'OpenPGP',
};

const isJws = (text: string): boolean => {
    const parts = text
        .trim()
        .replace(/^Bearer\s+/i, '')
        .split('.');
    if ((parts.length !== 3 && parts.length !== 5) || !parts.every((part) => /^[A-Za-z0-9_-]*$/.test(part)) || !parts[0]) return false;
    const header = decodeBase64Url(parts[0]);
    if (!header) return false;
    try {
        const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(header));
        return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed);
    } catch {
        return false;
    }
};

const isCose = (text: string): boolean => {
    const compact = text.replace(/\s+/g, '').replace(/^0x/i, '');
    if (compact.length < 40 || compact.length > 2_000_000) return false;
    const bytes = parseHex(compact) ?? parseBase64(compact);
    // a plain Ed25519 signature is 64 bytes: a COSE message holds one and more
    if (!bytes || bytes.length <= 64) return false;
    try {
        let value = decodeCbor(bytes);
        while (value instanceof Tagged && (value.tag === 61 || value.tag === 18 || value.tag === 98)) value = value.value;
        return (
            Array.isArray(value) &&
            value.length === 4 &&
            isBytes(value[0]) &&
            value[1] instanceof Map &&
            (isBytes(value[2]) || value[2] === null) &&
            // a COSE_Sign1 holds a signature, a COSE_Sign a list of them
            (isBytes(value[3]) || (Array.isArray(value[3]) && value[3].length > 0 && value[3].every(Array.isArray)))
        );
    } catch {
        return false;
    }
};

/** The container a text is, or null when it is not one (it may well be a plain signature). */
export function detectContainer(text: string): Container | null {
    const trimmed = text.trim();
    if (!trimmed) return null;
    if (trimmed.includes('-----BEGIN SSH SIGNATURE-----')) return 'sshsig';
    if (trimmed.includes('-----BEGIN PGP SIGNATURE-----') || trimmed.includes('-----BEGIN PGP SIGNED MESSAGE-----')) return 'pgp';
    if (/^untrusted comment:/.test(trimmed) && /\r?\ntrusted comment:/.test(trimmed)) return 'minisign';
    if (looksLikeSignify(trimmed)) return 'signify';
    if (isJws(trimmed)) return 'jws';
    if (isCose(trimmed)) return 'cose';
    return null;
}

export interface VerifyFields {
    signature: string;
    publicKey: string;
    message: string;
    messageFormat: MessageFormat;
}

export type Handoff =
    | { format: 'jws'; shared: Partial<SharedToken> }
    | { format: 'sshsig'; shared: Partial<SharedSshsig> }
    | { format: 'minisign'; shared: Partial<SharedMinisign> }
    | { format: 'signify'; shared: Partial<SharedSignify> }
    | { format: 'cose'; shared: Partial<SharedCose> }
    | { format: 'pgp'; shared: Partial<SharedPgp> };

/** What each container takes from the Verify tab: the signature where it goes, the key, and the message when the format has one. */
export function handoffFor(format: Container, { signature, publicKey, message, messageFormat }: VerifyFields): Handoff {
    const text = signature.trim();
    switch (format) {
        case 'jws':
            // a token holds its payload: there is no message to carry
            return { format, shared: { token: text, publicKey } };
        case 'sshsig':
            return { format, shared: { signature: text, publicKey, namespace: '', message, messageFormat } };
        case 'minisign':
        case 'signify':
            return { format, shared: { signature: text, publicKey, message, messageFormat } };
        case 'pgp':
            return { format, shared: { signature: text, publicKey, message, messageFormat } };
        case 'cose':
            // the message of the Verify tab is the payload, when the COSE message holds none
            return { format, shared: { message: text, publicKey, payload: message, payloadFormat: messageFormat, externalData: '' } };
    }
}
