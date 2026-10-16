/**
 * A JWK Set (RFC 7517 section 5), the document an issuer of tokens publishes: `{"keys": [{"kty":"OKP","crv":"Ed25519","kid":"…","x":"…"}, …]}`.
 * The header of a token says which key signed it (`kid`); this picks that key from the set the user pasted. It never guesses: no match,
 * several matches, or a token with no `kid` and several keys all end in an explanation (or a choice for the user), not in a key.
 * The key always comes from the set the user gave, never from the token. Pure functions.
 */
import { parseBase64 } from './bytes';

export class JwksError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'JwksError';
    }
}

export interface SetKey {
    /** its position among the keys of the set that count (Ed25519 ones), from 1 */
    position: number;
    kid?: string;
    publicKey: Uint8Array;
}

export interface JwkSet {
    keys: SetKey[];
    /** keys of other types (RSA, EC, X25519...) that were left out */
    ignored: number;
}

const shown = (value: string) => JSON.stringify(value.length > 40 ? `${value.slice(0, 40)}…` : value);

const asObject = (text: string): Record<string, unknown> | null => {
    try {
        const parsed: unknown = JSON.parse(text);
        return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
    } catch {
        return null;
    }
};

/** Is this text a JWK Set (a JSON object with a "keys" array)? A single key, or anything else, is not. */
export const looksLikeJwkSet = (text: string): boolean => {
    const object = text.trimStart().startsWith('{') ? asObject(text) : null;
    return !!object && Array.isArray(object.keys);
};

/** Reads a JWK Set: the Ed25519 keys count, the others are counted and left out. */
export function parseJwkSet(text: string): JwkSet {
    const object = asObject(text);
    if (!object || !Array.isArray(object.keys)) throw new JwksError('A JWK Set is a JSON object with a "keys" array.');
    const keys: SetKey[] = [];
    let ignored = 0;
    object.keys.forEach((entry: unknown, index) => {
        const jwk = typeof entry === 'object' && entry !== null && !Array.isArray(entry) ? (entry as Record<string, unknown>) : null;
        if (!jwk) throw new JwksError(`Entry ${index + 1} of the set is not a JSON object.`);
        if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
            ignored++;
            return;
        }
        const x = typeof jwk.x === 'string' ? parseBase64(jwk.x) : null;
        if (x?.length !== 32)
            throw new JwksError(`Entry ${index + 1} of the set is an Ed25519 key but its "x" is not 32 bytes in base64url.`);
        if (jwk.kid !== undefined && typeof jwk.kid !== 'string')
            throw new JwksError(`The "kid" of entry ${index + 1} of the set is not a text.`);
        keys.push({ position: keys.length + 1, kid: jwk.kid as string | undefined, publicKey: x });
    });
    return { keys, ignored };
}

export type Selection =
    /** the key to verify with, and what to tell the user about how it was picked */
    | { key: SetKey; note: string }
    /** no key can be picked: say why */
    | { error: string }
    /** several keys could be it and the token does not say: the user decides */
    | { choose: SetKey[]; error: string };

const label = (key: SetKey) => (key.kid !== undefined ? shown(key.kid) : `number ${key.position}`);
const others = (set: JwkSet) => (set.ignored ? ` (${set.ignored} other key${set.ignored === 1 ? '' : 's'} of another type left out)` : '');

/** Picks the key of the set for a token, by its `kid`. `chosen` is the position the user picked when the token does not name one. */
export function selectKey(set: JwkSet, kid: unknown, chosen?: number): Selection {
    if (set.keys.length === 0) {
        return {
            error: `The set has no Ed25519 key${set.ignored ? ` (its ${set.ignored} key${set.ignored === 1 ? ' is' : 's are'} of another type)` : ''}.`,
        };
    }
    if (kid !== undefined && typeof kid !== 'string') return { error: 'The "kid" in the header of the token is not a text.' };
    if (typeof kid === 'string') {
        const matches = set.keys.filter((key) => key.kid === kid);
        if (matches.length === 1) {
            return { key: matches[0], note: `Using the key ${shown(kid)} of the set, as the token asks${others(set)}.` };
        }
        if (matches.length > 1) {
            return { error: `Two keys of the set have the kid ${shown(kid)}: it is not possible to tell which one signed.` };
        }
        const names = set.keys.map(label).join(', ');
        return { error: `The set has no key ${shown(kid)}, the one the token names. It has: ${names}.` };
    }
    if (set.keys.length === 1) {
        return { key: set.keys[0], note: `The token names no key and the set has one Ed25519 key: using it${others(set)}.` };
    }
    const picked = chosen === undefined ? undefined : set.keys.find((key) => key.position === chosen);
    if (picked) return { key: picked, note: `Using the key ${label(picked)} of the set, the one you picked${others(set)}.` };
    return {
        choose: set.keys,
        error: `The token names no key (no "kid") and the set has ${set.keys.length} Ed25519 keys: pick the one to verify with.`,
    };
}

export const keyChoiceLabel = (key: SetKey): string => `Use the key ${label(key)}`;
