/**
 * A DID document (W3C DID Core), the document that says which keys a `did:web`, `did:jwk`... identifier uses: its `verificationMethod`
 * entries hold the public keys as a JWK (`publicKeyJwk`), as multibase (`publicKeyMultibase`, `z6Mk…`) or as base58 (`publicKeyBase58`,
 * the older form). The page never resolves a DID (it fetches nothing): the user pastes the document. The Ed25519 keys are read as a
 * key set, picked by the `id` of the method the way a JWK Set is picked by `kid`. Pure functions.
 */
import { parseBase64 } from './bytes';
import { CODECS } from './codecs';
import { EcosystemError, parseEcosystemKey } from './ecosystems';
import { JwksError, type JwkSet, type SetKey } from './jwks';

const asObject = (value: unknown): Record<string, unknown> | null =>
    typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;

/** The document itself: a DID resolution result wraps it in `didDocument`. */
const documentOf = (text: string): Record<string, unknown> | null => {
    if (!text.trimStart().startsWith('{')) return null;
    let parsed: unknown;
    try {
        parsed = JSON.parse(text);
    } catch {
        return null;
    }
    const object = asObject(parsed);
    return asObject(object?.didDocument) ?? object;
};

/** Is this text a DID document (a JSON object with a `verificationMethod` array)? */
export const looksLikeDidDocument = (text: string): boolean => Array.isArray(documentOf(text)?.verificationMethod);

const shown = (value: unknown) => JSON.stringify(String(value).length > 40 ? `${String(value).slice(0, 40)}…` : String(value));

/** The Ed25519 key a verification method holds, null when it holds another kind of key. */
function methodKey(method: Record<string, unknown>, label: string): Uint8Array | null {
    const jwk = asObject(method.publicKeyJwk);
    if (jwk) {
        if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return null;
        const x = typeof jwk.x === 'string' ? parseBase64(jwk.x) : null;
        if (x?.length !== 32) throw new JwksError(`The "x" of the key of ${label} is not 32 bytes in base64url.`);
        return x;
    }
    if (typeof method.publicKeyMultibase === 'string') {
        const text = method.publicKeyMultibase.trim();
        // a multibase text of another key type (z6LS… X25519, zQ3s… secp256k1, zDn… P-256) is not ours
        if (!text.startsWith('z6Mk')) return null;
        try {
            return parseEcosystemKey(text).publicKey ?? null;
        } catch (error) {
            if (error instanceof EcosystemError) throw new JwksError(`The publicKeyMultibase of ${label} is not valid: ${error.message}`);
            throw error;
        }
    }
    if (typeof method.publicKeyBase58 === 'string') {
        if (!String(method.type).includes('Ed25519')) return null;
        const bytes = CODECS.base58.decode(method.publicKeyBase58.trim());
        if (bytes?.length !== 32) throw new JwksError(`The publicKeyBase58 of ${label} is not 32 bytes in base58.`);
        return bytes;
    }
    return null;
}

/**
 * The Ed25519 keys of a DID document, as a key set whose `kid` is the id of the method. Methods are taken from `verificationMethod` and
 * from the ones embedded in `authentication`, `assertionMethod`..., once each. A relative id (`#key-1`) is made absolute with the id of
 * the document. Which verification relationship a key has is not looked at: the page checks a signature, it does not decide a policy.
 */
export function parseDidDocument(text: string): JwkSet {
    const document = documentOf(text);
    if (!document || !Array.isArray(document.verificationMethod)) {
        throw new JwksError('A DID document is a JSON object with a "verificationMethod" array.');
    }
    const did = typeof document.id === 'string' ? document.id : '';
    const methods: Record<string, unknown>[] = [];
    for (const [index, entry] of document.verificationMethod.entries()) {
        const method = asObject(entry);
        if (!method) throw new JwksError(`Entry ${index + 1} of the verification methods is not a JSON object.`);
        methods.push(method);
    }
    for (const relationship of ['authentication', 'assertionMethod', 'capabilityInvocation', 'capabilityDelegation', 'keyAgreement']) {
        const list = document[relationship];
        if (Array.isArray(list)) for (const entry of list) if (asObject(entry)) methods.push(asObject(entry) as Record<string, unknown>);
    }

    const keys: SetKey[] = [];
    const seen = new Set<string>();
    let ignored = 0;
    for (const method of methods) {
        const rawId = typeof method.id === 'string' ? method.id : '';
        const id = rawId.startsWith('#') && did ? `${did}${rawId}` : rawId;
        if (id && seen.has(id)) continue;
        if (id) seen.add(id);
        const publicKey = methodKey(method, id ? shown(id) : `entry ${methods.indexOf(method) + 1}`);
        if (!publicKey) {
            ignored++;
            continue;
        }
        const fragment = id.includes('#') ? id.slice(id.indexOf('#')) : '';
        keys.push({
            position: keys.length + 1,
            kid: id || undefined,
            // a token names the method with the whole id, with its fragment (#key-1) or with the fragment alone (key-1)
            aliases: fragment ? [fragment, fragment.slice(1)] : [],
            publicKey,
        });
    }
    return { keys, ignored, what: 'DID document' };
}
