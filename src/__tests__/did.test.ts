import { bytesToHex } from '../bytes';
import { looksLikeDidDocument, parseDidDocument } from '../did';
import { encodeEcosystemPublic } from '../ecosystems';
import { JwksError, selectKey } from '../jwks';
import { detectKeyFormat, KeyFormatError, parseStructuredKey } from '../keyformats';

// the keys of RFC 8037 and RFC 8032: public keys, in the three ways a DID document writes them
const KEY_1 = Buffer.from('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', 'base64url');
const KEY_2 = Buffer.from('HTAZSIhmy0zYZuoxA9tij6796Ai6Sm-_uDVPqvzc5Uw', 'base64url');
const multibase = (key: Buffer) => encodeEcosystemPublic(new Uint8Array(key), 'multibase');
const DID = 'did:web:example.com';
const document = (...methods: unknown[]) =>
    JSON.stringify({ '@context': ['https://www.w3.org/ns/did/v1'], id: DID, verificationMethod: methods });
const jwkMethod = (fragment: string, key: Buffer) => ({
    id: `${DID}#${fragment}`,
    type: 'JsonWebKey2020',
    controller: DID,
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: key.toString('base64url') },
});
const multibaseMethod = (fragment: string, key: Buffer) => ({
    id: `#${fragment}`,
    type: 'Ed25519VerificationKey2020',
    controller: DID,
    publicKeyMultibase: multibase(key),
});
const failure = (build: () => unknown) => {
    try {
        build();
    } catch (e) {
        return e instanceof JwksError || e instanceof KeyFormatError ? e.message : `other: ${e}`;
    }
    return 'no error';
};

describe('a DID document', () => {
    it('is told apart from a JWK, a JWK Set and anything else', () => {
        expect(looksLikeDidDocument(document(jwkMethod('k', KEY_1)))).toBe(true);
        expect(looksLikeDidDocument(JSON.stringify({ didDocument: JSON.parse(document(jwkMethod('k', KEY_1))) }))).toBe(true);
        expect(looksLikeDidDocument('{"keys":[]}')).toBe(false);
        expect(looksLikeDidDocument('{"kty":"OKP"}')).toBe(false);
        expect(looksLikeDidDocument('{"verificationMethod": 3}')).toBe(false);
        expect(looksLikeDidDocument('not json')).toBe(false);
    });

    it('reads a key written as a JWK, as multibase and as base58, the same bytes', () => {
        const base58 = { id: `${DID}#b`, type: 'Ed25519VerificationKey2018', controller: DID, publicKeyBase58: '' };
        // base58 of the 32 bytes, made by the page's own codec and checked by decoding it back with another one
        base58.publicKeyBase58 = encodeEcosystemPublic(new Uint8Array(KEY_1), 'near').slice('ed25519:'.length);
        const parsed = parseDidDocument(document(jwkMethod('a', KEY_1), multibaseMethod('m', KEY_1), base58));
        expect(parsed.what).toBe('DID document');
        expect(parsed.keys.map((key) => bytesToHex(key.publicKey))).toEqual([KEY_1, KEY_1, KEY_1].map((key) => key.toString('hex')));
        expect(parsed.keys.map((key) => key.kid)).toEqual([`${DID}#a`, `${DID}#m`, `${DID}#b`]); // a relative id is made absolute
    });

    it('leaves out the keys of other types, and counts them', () => {
        const parsed = parseDidDocument(
            document(
                jwkMethod('a', KEY_1),
                {
                    id: `${DID}#x`,
                    type: 'X25519KeyAgreementKey2020',
                    publicKeyMultibase: 'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc',
                },
                { id: `${DID}#e`, type: 'JsonWebKey2020', publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } },
                { id: `${DID}#s`, type: 'EcdsaSecp256k1VerificationKey2019', publicKeyBase58: '7' },
            ),
        );
        expect(parsed.keys).toHaveLength(1);
        expect(parsed.ignored).toBe(3);
    });

    it('takes the methods embedded in authentication or assertionMethod, once', () => {
        const embedded = jwkMethod('e', KEY_2);
        const doc = JSON.stringify({
            id: DID,
            verificationMethod: [jwkMethod('a', KEY_1), embedded],
            authentication: [`${DID}#a`, embedded],
            assertionMethod: [{ ...jwkMethod('only', KEY_1) }],
        });
        expect(parseDidDocument(doc).keys.map((key) => key.kid)).toEqual([`${DID}#a`, `${DID}#e`, `${DID}#only`]);
    });

    it('refuses what it cannot trust, with the reason', () => {
        expect(failure(() => parseDidDocument(document({ id: 'a', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } })))).toMatch(
            /not 32 bytes in base64url/,
        );
        expect(failure(() => parseDidDocument(document({ id: 'a', publicKeyMultibase: 'z6Mkabc' })))).toMatch(
            /publicKeyMultibase of "a" is not valid/,
        );
        expect(failure(() => parseDidDocument(document('a')))).toMatch(/not a JSON object/);
        expect(failure(() => parseDidDocument('{"verificationMethod": 3}'))).toMatch(/"verificationMethod" array/);
    });
});

describe('picking the method of a DID document by the kid of a token', () => {
    const set = parseDidDocument(document(jwkMethod('key-1', KEY_1), jwkMethod('key-2', KEY_2)));

    it.each([`${DID}#key-2`, '#key-2', 'key-2'])('%s names the method', (kid) => {
        const selection = selectKey(set, kid);
        expect('key' in selection && bytesToHex(selection.key.publicKey)).toBe(KEY_2.toString('hex'));
        expect('key' in selection && selection.note).toContain('of the DID document');
    });

    it('does not guess without a kid, or with a kid it does not have', () => {
        expect(selectKey(set, undefined)).toMatchObject({ error: expect.stringContaining('the DID document has 2 Ed25519 keys') });
        expect(selectKey(set, 'key-9')).toMatchObject({ error: expect.stringContaining('The DID document has no key "key-9"') });
    });
});

describe('a DID document where a key is expected', () => {
    it('is the key it holds, when it holds one', () => {
        const doc = document(multibaseMethod('k', KEY_1));
        expect(detectKeyFormat(doc)).toBe('DID document');
        expect(bytesToHex(parseStructuredKey(doc).publicKey!)).toBe(KEY_1.toString('hex'));
    });

    it('is refused when it holds several, naming them: nothing there picks one', () => {
        const message = failure(() => parseStructuredKey(document(jwkMethod('key-1', KEY_1), jwkMethod('key-2', KEY_2))));
        expect(message).toContain('has 2 Ed25519 keys');
        expect(message).toContain(`${DID}#key-1`);
        expect(failure(() => parseStructuredKey(document({ id: 'a', publicKeyJwk: { kty: 'EC' } })))).toMatch(/no Ed25519 key/);
    });
});
