/**
 * COSE_Sign1 (RFC 9052, with EdDSA from RFC 9053): the signed messages of CBOR, used by CWT, passkeys' attestations, mobile driving
 * licences, SCITT... A message is a CBOR array of four items
 *
 *     [ protected header (a byte string holding a CBOR map), unprotected header (a map), payload (bytes, or nil when it travels apart), signature ]
 *
 * and the signature is NOT over the payload: it is over `["Signature1", protected header, external data, payload]` written in CBOR.
 * The protected header is signed exactly as it came (its bytes, never rewritten), the unprotected one is not signed at all, which is
 * why the algorithm must be in the protected one. Also COSE_Sign (tag 98), a message with several signers, each signing
 * `["Signature", body protected, signer protected, external data, payload]`, and the claims of a CWT (RFC 8392). Pure functions:
 * the screen is in CosePanel.tsx.
 */
import * as ed from '@noble/ed25519';
import { bytesToHex, parseBase64, parseHex } from './bytes';
import { CborError, type CborKey, type CborValue, decodeCbor, encodeCbor, isBytes, Tagged } from './cbor';

export class CoseError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'CoseError';
    }
}

export const ALG_EDDSA = -8;
/** the fully-specified identifier of Ed25519 (RFC 9864), the same algorithm */
export const ALG_ED25519 = -19;

const KNOWN_ALGORITHMS: Record<number, string> = {
    [-7]: 'ES256',
    [-35]: 'ES384',
    [-36]: 'ES512',
    [-37]: 'PS256',
    [-38]: 'PS384',
    [-39]: 'PS512',
    [-257]: 'RS256',
    [-9]: 'ESP256',
    [-53]: 'Ed448',
};

export type Header = Map<CborKey, CborValue>;

export const HEADER_NAMES: Record<number, string> = {
    1: 'alg',
    2: 'crit',
    3: 'content type',
    4: 'kid',
    5: 'IV',
    6: 'partial IV',
    7: 'counter signature',
};

export interface ParsedCose {
    kind: 'sign1';
    /** the message was wrapped in the tag 18 (COSE_Sign1), and in the tag 61 (CWT) */
    tagged: boolean;
    cwt: boolean;
    /** the bytes of the protected header, as they came: this is what is signed */
    protectedBytes: Uint8Array;
    protectedHeader: Header;
    unprotectedHeader: Header;
    /** null: the payload travels apart */
    payload: Uint8Array | null;
    signature: Uint8Array;
    algorithm: number;
}

/** The bytes of a message written as text: hex (also with spaces or 0x), or base64 / base64url. */
export function bytesFromText(text: string): Uint8Array {
    const compact = text.replace(/\s+/g, '').replace(/^0x/i, '');
    if (!compact) throw new CoseError('The COSE message is empty.');
    const bytes = parseHex(compact) ?? parseBase64(compact);
    if (!bytes) throw new CoseError('The COSE message is bytes written as hex or base64; this text is neither.');
    return bytes;
}

const cbor = <T>(build: () => T): T => {
    try {
        return build();
    } catch (error) {
        if (error instanceof CborError) throw new CoseError(`Not a valid COSE message: ${error.message}`);
        throw error;
    }
};

const TAGS: Record<number, string> = {
    16: 'COSE_Encrypt0 (an encrypted message)',
    17: 'COSE_Mac0 (a message with a MAC)',
    96: 'COSE_Encrypt (an encrypted message)',
    97: 'COSE_Mac (a message with a MAC)',
};

const describeAlgorithm = (alg: CborValue): string => {
    if (typeof alg === 'number' && KNOWN_ALGORITHMS[alg]) return `${KNOWN_ALGORITHMS[alg]} (${alg})`;
    return typeof alg === 'number' ? String(alg) : JSON.stringify(typeof alg === 'string' ? alg.slice(0, 30) : 'unknown');
};

interface Unwrapped {
    kind: 'sign1' | 'sign';
    tagged: boolean;
    cwt: boolean;
    items: CborValue[];
}

/** The CBOR array of a signed message, whatever tags are around it (CWT, COSE_Sign1, COSE_Sign) or none. */
function unwrap(data: Uint8Array): Unwrapped {
    let value = cbor(() => decodeCbor(data));
    let tagged = false;
    let cwt = false;
    let kind: 'sign1' | 'sign' | null = null;
    if (value instanceof Tagged && value.tag === 61) {
        cwt = true;
        value = value.value;
    }
    if (value instanceof Tagged) {
        if (TAGS[value.tag]) throw new CoseError(`This is a ${TAGS[value.tag]}, not a signed one.`);
        if (value.tag !== 18 && value.tag !== 98) {
            throw new CoseError(`The message has the tag ${value.tag}, not the tag 18 of COSE_Sign1 or the tag 98 of COSE_Sign.`);
        }
        tagged = true;
        kind = value.tag === 18 ? 'sign1' : 'sign';
        value = value.value;
    }
    if (!Array.isArray(value) || value.length !== 4) {
        throw new CoseError(
            kind === 'sign'
                ? 'A COSE_Sign is a CBOR array of four items: protected header, unprotected header, payload, signatures.'
                : 'A COSE_Sign1 is a CBOR array of four items: protected header, unprotected header, payload, signature.',
        );
    }
    // without a tag, a list of signatures in the fourth place is what tells a COSE_Sign from a COSE_Sign1
    return { kind: kind ?? (Array.isArray(value[3]) ? 'sign' : 'sign1'), tagged, cwt, items: value };
}

/** Reads a COSE_Sign1 (tagged or not, also inside a CWT tag) and refuses what it cannot check, saying why. */
export function parseCose(data: Uint8Array): ParsedCose {
    const { kind, tagged, cwt, items } = unwrap(data);
    if (kind === 'sign') throw new CoseError('This is a COSE_Sign: a message with several signatures, not a COSE_Sign1.');
    return parseSign1(items, tagged, cwt);
}

/** The protected header: a byte string holding a map (or nothing, for an empty one), with no parameter also in the unprotected one. */
function readProtected(item: Uint8Array, unprotected: Header): Header {
    let header: Header = new Map();
    if (item.length > 0) {
        const decoded = cbor(() => decodeCbor(item));
        if (!(decoded instanceof Map)) throw new CoseError('The protected header does not hold a map.');
        header = decoded;
    }
    for (const label of header.keys()) {
        if (unprotected.has(label))
            throw new CoseError(`The header parameter ${label} is both in the protected and the unprotected header.`);
    }
    return header;
}

function parseSign1(items: CborValue[], tagged: boolean, cwt: boolean): ParsedCose {
    const [protectedItem, unprotectedItem, payload, signature] = items;
    if (!isBytes(protectedItem)) throw new CoseError('The protected header is not a byte string.');
    if (!(unprotectedItem instanceof Map)) throw new CoseError('The unprotected header is not a map.');
    if (payload !== null && !isBytes(payload)) throw new CoseError('The payload is neither bytes nor nil.');
    if (!isBytes(signature)) throw new CoseError('The signature is not a byte string.');
    const protectedHeader = readProtected(protectedItem, unprotectedItem);

    const algorithm = protectedHeader.get(1);
    if (algorithm === undefined) {
        throw new CoseError(
            unprotectedItem.has(1)
                ? 'The algorithm is in the unprotected header, which nothing signs: anyone could change it. It must be in the protected one.'
                : 'The protected header has no algorithm (label 1).',
        );
    }
    if (algorithm !== ALG_EDDSA && algorithm !== ALG_ED25519) {
        throw new CoseError(`The algorithm is ${describeAlgorithm(algorithm)}, only EdDSA (-8) with Ed25519 is supported.`);
    }
    if (protectedHeader.has(2) || unprotectedItem.has(2)) {
        throw new CoseError(
            'The header has "crit" (critical parameters), which this page does not process: it would not be right to call the signature valid.',
        );
    }
    if (signature.length !== 64) throw new CoseError(`The signature has ${signature.length} bytes, an Ed25519 signature has 64.`);
    return {
        kind: 'sign1',
        tagged,
        cwt,
        protectedBytes: protectedItem,
        protectedHeader,
        unprotectedHeader: unprotectedItem,
        payload,
        signature,
        algorithm,
    };
}

/** One of the signatures of a COSE_Sign. A signature this page cannot check is kept, with the reason: it is never skipped in silence. */
export interface CoseSigner {
    protectedBytes: Uint8Array;
    protectedHeader: Header;
    unprotectedHeader: Header;
    signature: Uint8Array;
    kid?: Uint8Array;
    /** why it cannot be checked (another algorithm, "crit"...) */
    problem?: string;
}

/** A COSE_Sign (tag 98): one payload, several signatures. */
export interface ParsedCoseSign {
    kind: 'sign';
    tagged: boolean;
    cwt: boolean;
    protectedBytes: Uint8Array;
    protectedHeader: Header;
    unprotectedHeader: Header;
    payload: Uint8Array | null;
    signers: CoseSigner[];
}

const MAX_SIGNERS = 64;

function parseSigner(item: CborValue, index: number): CoseSigner {
    const where = `Signature ${index + 1}`;
    if (!Array.isArray(item) || item.length !== 3) {
        throw new CoseError(`${where} is not a CBOR array of three items: protected header, unprotected header, signature.`);
    }
    const [protectedItem, unprotectedItem, signature] = item;
    if (!isBytes(protectedItem)) throw new CoseError(`The protected header of signature ${index + 1} is not a byte string.`);
    if (!(unprotectedItem instanceof Map)) throw new CoseError(`The unprotected header of signature ${index + 1} is not a map.`);
    if (!isBytes(signature)) throw new CoseError(`The signature ${index + 1} is not a byte string.`);
    const protectedHeader = readProtected(protectedItem, unprotectedItem);
    const kid = protectedHeader.get(4) ?? unprotectedItem.get(4);
    const algorithm = protectedHeader.get(1);
    let problem: string | undefined;
    if (algorithm === undefined) {
        problem = unprotectedItem.has(1)
            ? 'its algorithm is in the unprotected header, which nothing signs: it must be in the protected one'
            : 'its protected header has no algorithm (label 1)';
    } else if (algorithm !== ALG_EDDSA && algorithm !== ALG_ED25519) {
        problem = `its algorithm is ${describeAlgorithm(algorithm)}, only EdDSA (-8) with Ed25519 is supported`;
    } else if (protectedHeader.has(2) || unprotectedItem.has(2)) {
        problem = 'it has "crit" (critical parameters), which this page does not process';
    } else if (signature.length !== 64) {
        problem = `its signature has ${signature.length} bytes, an Ed25519 signature has 64`;
    }
    return {
        protectedBytes: protectedItem,
        protectedHeader,
        unprotectedHeader: unprotectedItem,
        signature,
        kid: isBytes(kid) ? kid : undefined,
        problem,
    };
}

function parseSign(items: CborValue[], tagged: boolean, cwt: boolean): ParsedCoseSign {
    const [protectedItem, unprotectedItem, payload, signatures] = items;
    if (!isBytes(protectedItem)) throw new CoseError('The protected header is not a byte string.');
    if (!(unprotectedItem instanceof Map)) throw new CoseError('The unprotected header is not a map.');
    if (payload !== null && !isBytes(payload)) throw new CoseError('The payload is neither bytes nor nil.');
    if (!Array.isArray(signatures)) throw new CoseError('The signatures of a COSE_Sign are a CBOR array.');
    if (signatures.length === 0) throw new CoseError('This COSE_Sign has no signature.');
    if (signatures.length > MAX_SIGNERS)
        throw new CoseError(`This COSE_Sign has ${signatures.length} signatures, more than the ${MAX_SIGNERS} read.`);
    const protectedHeader = readProtected(protectedItem, unprotectedItem);
    if (protectedHeader.has(2) || unprotectedItem.has(2)) {
        throw new CoseError(
            'The header has "crit" (critical parameters), which this page does not process: it would not be right to call the signatures valid.',
        );
    }
    return {
        kind: 'sign',
        tagged,
        cwt,
        protectedBytes: protectedItem,
        protectedHeader,
        unprotectedHeader: unprotectedItem,
        payload,
        signers: signatures.map(parseSigner),
    };
}

/** Reads a COSE_Sign1 or a COSE_Sign (tagged or not, also inside a CWT tag). */
export function parseCoseMessage(data: Uint8Array): ParsedCose | ParsedCoseSign {
    const { kind, tagged, cwt, items } = unwrap(data);
    return kind === 'sign' ? parseSign(items, tagged, cwt) : parseSign1(items, tagged, cwt);
}

/** What one signer of a COSE_Sign signs: `["Signature", body protected, signer protected, external data, payload]`, in CBOR. */
export const signedDataOfSigner = (
    bodyProtected: Uint8Array,
    signerProtected: Uint8Array,
    payload: Uint8Array,
    externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array => encodeCbor(['Signature', bodyProtected, signerProtected, externalAad, payload]);

/** What is really signed: `["Signature1", protected header, external data, payload]`, in CBOR. */
export const signedData = (protectedBytes: Uint8Array, payload: Uint8Array, externalAad: Uint8Array = new Uint8Array(0)): Uint8Array =>
    encodeCbor(['Signature1', protectedBytes, externalAad, payload]);

/** A COSE_Key (RFC 9052 section 7) of an Ed25519 key, when the bytes are one. */
export interface CoseKey {
    publicKey?: Uint8Array;
    privateKey?: Uint8Array;
    kid?: Uint8Array;
}

function coseKeyOf(map: CborValue): CoseKey {
    if (!(map instanceof Map)) throw new CoseError('A COSE_Key is a CBOR map.');
    if (map.get(1) !== 1) throw new CoseError('The COSE_Key is not of type OKP (kty 1), the type of Ed25519 keys.');
    if (map.get(-1) !== 6) throw new CoseError('The COSE_Key is not on the curve Ed25519 (crv 6).');
    const x = map.get(-2);
    const d = map.get(-4);
    const kid = map.get(2);
    if (!isBytes(x) && !isBytes(d)) throw new CoseError('The COSE_Key has neither a public (-2) nor a private (-4) part.');
    if (x !== undefined && (!isBytes(x) || x.length !== 32)) throw new CoseError('The public part (x) of the COSE_Key is not 32 bytes.');
    if (d !== undefined && (!isBytes(d) || d.length !== 32)) throw new CoseError('The private part (d) of the COSE_Key is not 32 bytes.');
    return {
        publicKey: x as Uint8Array | undefined,
        privateKey: d as Uint8Array | undefined,
        kid: isBytes(kid) ? kid : undefined,
    };
}

export function parseCoseKey(data: Uint8Array): CoseKey {
    return coseKeyOf(cbor(() => decodeCbor(data)));
}

/** A COSE_KeySet (RFC 9052 section 7.2): an array of COSE_Keys. The keys of other types or curves are of no use here and are left out. */
export function parseCoseKeySet(data: Uint8Array): CoseKey[] {
    const array = cbor(() => decodeCbor(data));
    if (!Array.isArray(array)) throw new CoseError('A COSE_KeySet is a CBOR array of COSE_Keys.');
    const keys: CoseKey[] = [];
    for (const item of array) {
        if (!(item instanceof Map)) throw new CoseError('A COSE_KeySet is a CBOR array of COSE_Keys.');
        if (item.get(1) === 1 && item.get(-1) === 6) keys.push(coseKeyOf(item));
    }
    if (keys.length === 0) throw new CoseError('The COSE_KeySet holds no Ed25519 key (kty 1, crv 6).');
    return keys;
}

/** Does this text hold a COSE_Key (hex or base64 of a CBOR map)? Other texts are keys in other formats. */
export function readCoseKey(text: string): CoseKey | null {
    const compact = text.replace(/\s+/g, '').replace(/^0x/i, '');
    // a CBOR map starts with a byte 0xa0-0xbf: "a" or "b" in hex, "o" or "p"..."v" in base64
    if (!/^(?:[ab][0-9a-f]|[o-v][A-Za-z0-9+/_-])/i.test(compact)) return null;
    try {
        return parseCoseKey(bytesFromText(text));
    } catch {
        return null;
    }
}

/**
 * The keys of a text that holds several: a COSE_KeySet (hex or base64), or one key per line, each a COSE_Key or a plain public key of
 * 32 bytes (hex or base64). Null for anything else, which is a single key in some other format.
 */
export function readCoseKeys(text: string): CoseKey[] | null {
    const compact = text.replace(/\s+/g, '').replace(/^0x/i, '');
    // a CBOR array starts with a byte 0x80-0x9f: "8" or "9" in hex, "g"..."n" in base64
    if (/^(?:[89][0-9a-f]|[g-n][A-Za-z0-9+/_-])/i.test(compact)) {
        try {
            return parseCoseKeySet(bytesFromText(text));
        } catch {
            // the first byte of a plain key can look like this: it may be one key per line
        }
    }
    const lines = text.split(/\r?\n/).filter((line) => line.trim());
    if (lines.length < 2) return null;
    const keys: CoseKey[] = [];
    for (const line of lines) {
        const key = readCoseKey(line);
        if (key) {
            keys.push(key);
            continue;
        }
        const bytes = parseHex(line.trim().replace(/^0x/i, '')) ?? parseBase64(line.trim());
        if (bytes?.length !== 32) return null;
        keys.push({ publicKey: bytes });
    }
    return keys;
}

export function encodeCoseKey(publicKey: Uint8Array, kid?: Uint8Array): Uint8Array {
    const map = new Map<CborKey, CborValue>([
        [1, 1],
        [-1, 6],
        [-2, publicKey],
    ]);
    if (kid?.length) map.set(2, kid);
    return encodeCbor(map);
}

export interface CoseOptions {
    kid?: Uint8Array;
    /** a number (CoAP content format) or a media type */
    contentType?: number | string;
    externalAad?: Uint8Array;
    detached?: boolean;
    tagged?: boolean;
}

/** Signs the way a COSE library does: protected `{1: -8}` (and the content type), the key id in the unprotected header. */
export async function signCose(payload: Uint8Array, seed: Uint8Array, options: CoseOptions = {}): Promise<Uint8Array> {
    const protectedHeader = new Map<CborKey, CborValue>([[1, ALG_EDDSA]]);
    if (options.contentType !== undefined) protectedHeader.set(3, options.contentType);
    const unprotected = new Map<CborKey, CborValue>();
    if (options.kid?.length) unprotected.set(4, options.kid);
    const protectedBytes = encodeCbor(protectedHeader);
    const signature = await ed.signAsync(signedData(protectedBytes, payload, options.externalAad), seed);
    const message = [protectedBytes, unprotected, options.detached ? null : payload, signature];
    return encodeCbor(options.tagged === false ? message : new Tagged(18, message));
}

/** The claims of a CWT (RFC 8392 section 3.1) that have a name. */
export const CWT_CLAIM_NAMES: Record<number, string> = {
    1: 'iss (issuer)',
    2: 'sub (subject)',
    3: 'aud (audience)',
    4: 'exp (expiration time)',
    5: 'nbf (not before)',
    6: 'iat (issued at)',
    7: 'cti (CWT ID)',
};

/** the largest time a JavaScript date holds (8.64e15 milliseconds) */
const MAX_SECONDS = 8.64e12;

export interface CwtClaims {
    claims: Array<{ key: CborKey; name: string | null; value: CborValue }>;
    /** the times of the token in seconds, when they are numbers */
    exp?: number;
    nbf?: number;
    iat?: number;
    /** what could not be understood: a time that is not a number */
    problems: string[];
}

/**
 * The payload of a CWT: a CBOR map of claims. Null when the payload is not CBOR or not a map (a text is never one: a map starts with
 * a byte that is not valid at the start of UTF-8). It is what the token says, not what the signature proves.
 */
export function readCwtClaims(payload: Uint8Array): CwtClaims | null {
    let map: CborValue;
    try {
        map = decodeCbor(payload);
    } catch {
        return null;
    }
    if (!(map instanceof Map)) return null;
    const result: CwtClaims = {
        claims: Array.from(map, ([key, value]) => ({ key, name: typeof key === 'number' ? (CWT_CLAIM_NAMES[key] ?? null) : null, value })),
        problems: [],
    };
    for (const [key, name] of [
        [4, 'exp'],
        [5, 'nbf'],
        [6, 'iat'],
    ] as const) {
        const value = map.get(key);
        if (value === undefined) continue;
        if (typeof value === 'number' && Math.abs(value) <= MAX_SECONDS) result[name] = value;
        else result.problems.push(`The claim ${name} is not a number of seconds a date can hold, so its time is not checked.`);
    }
    return result;
}

export type SignerVerdict = 'valid' | 'invalid' | 'permissive-only' | 'not-checked';

export interface SignerResult {
    verdict: SignerVerdict;
    /** why it was not checked */
    reason?: string;
    /** which of the given keys verified it (from 0) */
    keyIndex?: number;
}

const kidText = (kid: Uint8Array) => {
    const text = new TextDecoder().decode(kid);
    return /^[\x20-\x7e]+$/.test(text) && text.length <= 40 ? `"${text}"` : `h'${bytesToHex(kid).slice(0, 40)}'`;
};
const sameBytes = (a: Uint8Array, b: Uint8Array) => bytesToHex(a) === bytesToHex(b);

/**
 * Verifies each signature of a COSE_Sign with the keys given. A signature is checked with the keys that name the same kid (or, when
 * none does, the keys that name none); without a kid it is tried with all of them. One that has no key, or no given key verifies, or that this page cannot
 * check, is "not-checked" and says why: it is never counted as valid.
 */
export async function verifySigners(
    parsed: ParsedCoseSign,
    payload: Uint8Array,
    externalAad: Uint8Array,
    keys: CoseKey[],
    check: (signature: Uint8Array, data: Uint8Array, publicKey: Uint8Array) => Promise<'valid' | 'invalid' | 'permissive-only'>,
): Promise<SignerResult[]> {
    const usable = keys.flatMap((key, index) => (key.publicKey ? [{ ...key, index }] : []));
    const results: SignerResult[] = [];
    for (const signer of parsed.signers) {
        if (signer.problem) {
            results.push({ verdict: 'not-checked', reason: `Not checked: ${signer.problem}.` });
            continue;
        }
        let candidates = usable;
        if (signer.kid) {
            const named = usable.filter((key) => key.kid && sameBytes(key.kid, signer.kid as Uint8Array));
            candidates = named.length ? named : usable.filter((key) => !key.kid);
        }
        if (candidates.length === 0) {
            results.push({
                verdict: 'not-checked',
                reason: signer.kid
                    ? `Not checked: no key was given for the key id ${kidText(signer.kid)}.`
                    : 'Not checked: no key was given.',
            });
            continue;
        }
        const data = signedDataOfSigner(parsed.protectedBytes, signer.protectedBytes, payload, externalAad);
        let result: SignerResult = { verdict: 'invalid' };
        for (const key of candidates) {
            const verdict = await check(signer.signature, data, key.publicKey as Uint8Array);
            if (verdict === 'valid') {
                result = { verdict, keyIndex: key.index };
                break;
            }
            if (verdict === 'permissive-only') result = { verdict, keyIndex: key.index };
        }
        // no kid and several keys: failing every one only means that the key of this signature may not be among them
        if (result.verdict === 'invalid' && !signer.kid && usable.length > 1) {
            result = {
                verdict: 'not-checked',
                reason: `Not checked: it names no key id and none of the ${usable.length} keys given verifies it; it may be made by another key.`,
            };
        }
        results.push(result);
    }
    return results;
}

/** The verdict for the whole message: valid only when every signature was checked and is valid. */
export function summarizeSigners(results: SignerResult[]) {
    const count = (verdict: SignerVerdict) => results.filter((result) => result.verdict === verdict).length;
    const valid = count('valid');
    const invalid = count('invalid');
    const permissive = count('permissive-only');
    const notChecked = count('not-checked');
    const total = results.length;
    const overall: 'valid' | 'invalid' | 'permissive-only' | 'incomplete' =
        invalid > 0 ? 'invalid' : permissive > 0 ? 'permissive-only' : notChecked > 0 ? 'incomplete' : 'valid';
    return { valid, invalid, permissive, notChecked, total, overall };
}
