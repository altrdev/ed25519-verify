import { JwksError, keyChoiceLabel, looksLikeJwkSet, parseJwkSet, selectKey } from '../jwks';

const X1 = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const X2 = 'HTAZSIhmy0zYZuoxA9tij6796Ai6Sm-_uDVPqvzc5Uw';
const okp = (x: string, kid?: string) => ({ kty: 'OKP', crv: 'Ed25519', x, ...(kid !== undefined && { kid }) });
const set = (...keys: unknown[]) => JSON.stringify({ keys });
const failure = (build: () => unknown) => {
    try {
        build();
    } catch (e) {
        return e instanceof JwksError ? e.message : `other: ${e}`;
    }
    return 'no error';
};

describe('a JWK Set', () => {
    it('is told apart from a single key and from anything else', () => {
        expect(looksLikeJwkSet(set(okp(X1)))).toBe(true);
        expect(looksLikeJwkSet(set())).toBe(true);
        expect(looksLikeJwkSet(JSON.stringify(okp(X1)))).toBe(false);
        expect(looksLikeJwkSet('{"keys": 3}')).toBe(false);
        expect(looksLikeJwkSet('[{"keys":[]}]')).toBe(false);
        expect(looksLikeJwkSet('not json {"keys":[]}')).toBe(false);
        expect(looksLikeJwkSet('')).toBe(false);
    });

    it('keeps the Ed25519 keys and counts the others', () => {
        const parsed = parseJwkSet(
            set(
                okp(X1, 'a'),
                { kty: 'RSA', kid: 'r', n: 'AQAB', e: 'AQAB' },
                { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' },
                { kty: 'OKP', crv: 'X25519', x: X1 },
                okp(X2, 'b'),
            ),
        );
        expect(parsed.ignored).toBe(3);
        expect(parsed.keys.map((key) => [key.position, key.kid])).toEqual([
            [1, 'a'],
            [2, 'b'],
        ]);
        expect(parsed.keys[0].publicKey).toHaveLength(32);
    });

    it('refuses what is malformed, naming the entry', () => {
        expect(failure(() => parseJwkSet('{"keys": 3}'))).toMatch(/"keys" array/);
        expect(failure(() => parseJwkSet(set(okp(X1), 3)))).toMatch(/Entry 2 .* not a JSON object/);
        expect(failure(() => parseJwkSet(set({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' })))).toMatch(/Entry 1 .* "x" is not 32 bytes/);
        expect(failure(() => parseJwkSet(set({ ...okp(X1), kid: 7 })))).toMatch(/"kid" of entry 1/);
    });
});

describe('picking the key of the token', () => {
    const two = parseJwkSet(set(okp(X1, 'key-1'), okp(X2, 'key-2'), { kty: 'RSA' }));

    it('takes the one the token names, and says so', () => {
        const selection = selectKey(two, 'key-2');
        expect('key' in selection && selection.key.position).toBe(2);
        expect('note' in selection && selection.note).toBe(
            'Using the key "key-2" of the set, as the token asks (1 other key of another type left out).',
        );
    });

    it('does not guess when there is no such key, and lists the ones there are', () => {
        const selection = selectKey(two, 'key-3');
        expect(selection).toEqual({ error: 'The set has no key "key-3", the one the token names. It has: "key-1", "key-2".' });
    });

    it('refuses two keys with the same kid', () => {
        const duplicated = parseJwkSet(set(okp(X1, 'same'), okp(X2, 'same')));
        expect(selectKey(duplicated, 'same')).toEqual({ error: expect.stringMatching(/Two keys of the set have the kid "same"/) });
    });

    it('with a token that names no key: the only key is used, several are a choice, and a choice settles it', () => {
        const single = parseJwkSet(set(okp(X1), { kty: 'RSA' }));
        expect(selectKey(single, undefined)).toMatchObject({ note: expect.stringMatching(/names no key and the set has one Ed25519 key/) });

        const choice = selectKey(two, undefined);
        expect('choose' in choice && choice.choose.map(keyChoiceLabel)).toEqual(['Use the key "key-1"', 'Use the key "key-2"']);
        expect('error' in choice && choice.error).toMatch(/names no key \(no "kid"\) and the set has 2 Ed25519 keys: pick/);
        const picked = selectKey(two, undefined, 2);
        expect('key' in picked && picked.key.kid).toBe('key-2');
        expect(selectKey(two, undefined, 9)).toHaveProperty('choose'); // a position that is not there is no choice
    });

    it('a key with no kid is named by its position', () => {
        const mixed = parseJwkSet(set(okp(X1), okp(X2, 'b')));
        expect(selectKey(mixed, undefined)).toHaveProperty('choose');
        expect(selectKey(mixed, 'x')).toEqual({ error: expect.stringContaining('It has: number 1, "b".') });
        expect(keyChoiceLabel(mixed.keys[0])).toBe('Use the key number 1');
    });

    it('explains a set with no Ed25519 key, and a kid that is not a text', () => {
        const none = parseJwkSet(set({ kty: 'RSA' }, { kty: 'EC', crv: 'P-256' }));
        expect(selectKey(none, 'a')).toEqual({ error: 'The set has no Ed25519 key (its 2 keys are of another type).' });
        expect(selectKey(parseJwkSet(set()), undefined)).toEqual({ error: 'The set has no Ed25519 key.' });
        expect(selectKey(two, 7)).toEqual({ error: expect.stringMatching(/not a text/) });
    });

    it('a kid is matched exactly (case and all)', () => {
        expect(selectKey(two, 'KEY-2')).toHaveProperty('error');
    });
});
