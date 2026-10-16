/**
 * COSE_Sign1 (RFC 9052, with EdDSA from RFC 9053): the signed messages of CBOR, used by CWT, passkeys' attestations, mobile driving
 * licences, SCITT... A message is a CBOR array of four items
 *
 *     [ protected header (a byte string holding a CBOR map), unprotected header (a map), payload (bytes, or nil when it travels apart), signature ]
 *
 * and the signature is NOT over the payload: it is over `["Signature1", protected header, external data, payload]` written in CBOR.
 * The protected header is signed exactly as it came (its bytes, never rewritten), the unprotected one is not signed at all, which is
 * why the algorithm must be in the protected one. Pure functions: the screen is in CosePanel.tsx.
 */
import * as ed from '@noble/ed25519';
import { parseBase64, parseHex } from './bytes';
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

/** Reads a COSE_Sign1 (tagged or not, also inside a CWT tag) and refuses what it cannot check, saying why. */
export function parseCose(data: Uint8Array): ParsedCose {
    let value = cbor(() => decodeCbor(data));
    let tagged = false;
    let cwt = false;
    if (value instanceof Tagged && value.tag === 61) {
        cwt = true;
        value = value.value;
    }
    if (value instanceof Tagged) {
        if (value.tag === 98) {
            throw new CoseError('This is a COSE_Sign: a message with several signatures. Only COSE_Sign1 (one signature) is supported.');
        }
        if (TAGS[value.tag]) throw new CoseError(`This is a ${TAGS[value.tag]}, not a signed one.`);
        if (value.tag !== 18) throw new CoseError(`The message has the tag ${value.tag}, not the tag 18 of COSE_Sign1.`);
        tagged = true;
        value = value.value;
    }
    if (!Array.isArray(value) || value.length !== 4) {
        throw new CoseError('A COSE_Sign1 is a CBOR array of four items: protected header, unprotected header, payload, signature.');
    }
    const [protectedItem, unprotectedItem, payload, signature] = value;
    if (!isBytes(protectedItem)) throw new CoseError('The protected header is not a byte string.');
    if (!(unprotectedItem instanceof Map)) throw new CoseError('The unprotected header is not a map.');
    if (payload !== null && !isBytes(payload)) throw new CoseError('The payload is neither bytes nor nil.');
    if (!isBytes(signature)) throw new CoseError('The signature is not a byte string.');
    let protectedHeader: Header = new Map();
    if (protectedItem.length > 0) {
        const decoded = cbor(() => decodeCbor(protectedItem));
        if (!(decoded instanceof Map)) throw new CoseError('The protected header does not hold a map.');
        protectedHeader = decoded;
    }
    for (const label of protectedHeader.keys()) {
        if (unprotectedItem.has(label))
            throw new CoseError(`The header parameter ${label} is both in the protected and the unprotected header.`);
    }

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

/** What is really signed: `["Signature1", protected header, external data, payload]`, in CBOR. */
export const signedData = (protectedBytes: Uint8Array, payload: Uint8Array, externalAad: Uint8Array = new Uint8Array(0)): Uint8Array =>
    encodeCbor(['Signature1', protectedBytes, externalAad, payload]);

/** A COSE_Key (RFC 9052 section 7) of an Ed25519 key, when the bytes are one. */
export interface CoseKey {
    publicKey?: Uint8Array;
    privateKey?: Uint8Array;
    kid?: Uint8Array;
}

export function parseCoseKey(data: Uint8Array): CoseKey {
    const map = cbor(() => decodeCbor(data));
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
