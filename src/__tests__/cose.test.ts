import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '../bytes';
import { decodeCbor, Tagged } from '../cbor';
import {
    bytesFromText,
    CoseError,
    encodeCoseKey,
    parseCose,
    parseCoseKey,
    parseCoseMessage,
    readCoseKey,
    readCoseKeys,
    readCwtClaims,
    signCose,
    signedData,
    summarizeSigners,
    verifySigners,
} from '../cose';
import {
    COSE_AAD,
    COSE_ATTACHED,
    COSE_ATTACHED_PAYLOAD,
    COSE_ATTACHED_TO_BE_SIGNED,
    COSE_DETACHED,
    COSE_KEY_HEX,
    COSE_MESSAGE,
    COSE_PLAIN,
    COSE_PUBLIC,
    COSE_SEED,
    COSE_UNTAGGED_KID,
    COSE_KEY_ALICE,
    COSE_KEY_BOB,
    COSE_KEYSET_AB,
    COSE_MISC_CLAIMS,
    COSE_PUBLIC_2,
    COSE_PUBLIC_3,
    CWT_LONG,
    CWT_RFC8392,
    CWT_RFC8392_CLAIMS,
    SIGN_THREE,
    SIGN_TWO,
    SIGN_TWO_AAD,
    SIGN_TWO_AAD_DETACHED,
} from './fixtures/cose';

const publicKey = hexToBytes(COSE_PUBLIC);
const seed = hexToBytes(COSE_SEED);
const text = (s: string) => new TextEncoder().encode(s);
const strict = { zip215: false };
const failure = (build: () => unknown) => {
    try {
        build();
    } catch (e) {
        return e instanceof CoseError ? e.message : `other: ${e}`;
    }
    return 'no error';
};
const verified = async (hex: string, payload?: Uint8Array, aad?: Uint8Array) => {
    const parsed = parseCose(hexToBytes(hex));
    const data = signedData(parsed.protectedBytes, parsed.payload ?? (payload as Uint8Array), aad);
    return ed.verifyAsync(parsed.signature, data, publicKey, strict);
};

describe('messages made by other COSE libraries', () => {
    it('the example of the COSE working group: read, its ToBeSigned bytes are theirs, and the signature verifies', async () => {
        const parsed = parseCose(hexToBytes(COSE_ATTACHED));
        expect(parsed).toMatchObject({ tagged: true, cwt: false, algorithm: -8 });
        expect(new TextDecoder().decode(parsed.payload as Uint8Array)).toBe(COSE_ATTACHED_PAYLOAD);
        expect(parsed.protectedHeader).toEqual(
            new Map([
                [1, -8],
                [3, 0],
            ]),
        );
        expect(bytesToHex(parsed.unprotectedHeader.get(4) as Uint8Array)).toBe('3131');
        expect(bytesToHex(signedData(parsed.protectedBytes, parsed.payload as Uint8Array))).toBe(COSE_ATTACHED_TO_BE_SIGNED);
        expect(await verified(COSE_ATTACHED)).toBe(true);
    });

    it('a message with a payload, one without the tag, one with external data, one with the payload apart', async () => {
        expect(await verified(COSE_PLAIN)).toBe(true);
        expect(parseCose(hexToBytes(COSE_UNTAGGED_KID))).toMatchObject({ tagged: false });
        expect(await verified(COSE_UNTAGGED_KID)).toBe(true);
        expect(await verified(COSE_AAD, undefined, text('context'))).toBe(true);
        expect(await verified(COSE_AAD)).toBe(false); // without the external data
        expect(parseCose(hexToBytes(COSE_DETACHED)).payload).toBeNull();
        expect(await verified(COSE_DETACHED, text(COSE_MESSAGE))).toBe(true);
        expect(await verified(COSE_DETACHED, text('hello world!'))).toBe(false);
    });

    it('reads a CWT (the tag 61 around the tag 18)', () => {
        const wrapped = `d83d${COSE_PLAIN}`;
        expect(parseCose(hexToBytes(wrapped))).toMatchObject({ cwt: true, tagged: true });
    });

    it('signs the protected header as it came, never rewritten', async () => {
        // the same map written with a longer integer (a valid CBOR): the signature covers these exact bytes
        const original = parseCose(hexToBytes(COSE_PLAIN));
        expect(bytesToHex(original.protectedBytes)).toBe('a10127');
        const other = signedData(hexToBytes(`${'a1010127'.slice(0, 0)}a10127`), text(COSE_MESSAGE));
        expect(bytesToHex(other)).toBe(bytesToHex(signedData(original.protectedBytes, text(COSE_MESSAGE))));
    });
});

describe('signing', () => {
    it('gives byte for byte the example of the COSE working group (content type, key id, tag)', async () => {
        const made = await signCose(text(COSE_ATTACHED_PAYLOAD), seed, { kid: text('11'), contentType: 0 });
        expect(bytesToHex(made)).toBe(COSE_ATTACHED);
    });

    it.each([
        ['plain', COSE_PLAIN, {}],
        ['untagged with a kid', COSE_UNTAGGED_KID, { kid: text('my-key'), tagged: false }],
        ['with external data', COSE_AAD, { externalAad: text('context') }],
        ['detached', COSE_DETACHED, { detached: true }],
    ])('gives byte for byte what pycose made: %s', async (_name, expected, options) => {
        expect(bytesToHex(await signCose(text(COSE_MESSAGE), seed, options))).toBe(expected);
    });

    it('writes a content type given as a media type', async () => {
        const parsed = parseCose(await signCose(text('{}'), seed, { contentType: 'application/json' }));
        expect(parsed.protectedHeader.get(3)).toBe('application/json');
    });
});

describe('what is refused, and why', () => {
    const build = (items: unknown[]) => {
        // [protected, unprotected, payload, signature] written by hand in hex
        return hexToBytes(items.join(''));
    };
    const sig = `5840${'00'.repeat(64)}`;

    it('is not one signature of Ed25519', () => {
        expect(failure(() => parseCose(hexToBytes(`d8628443a10127a04b68656c6c6f20776f726c64${sig}`)))).toMatch(
            /COSE_Sign: a message with several/,
        );
        expect(failure(() => parseCose(hexToBytes(`d18443a10127a04b68656c6c6f20776f726c64${sig}`)))).toMatch(/COSE_Mac0/);
        expect(failure(() => parseCose(hexToBytes(`d9ffff8443a10127a04b68656c6c6f20776f726c64${sig}`)))).toMatch(/tag 65535/);
        expect(failure(() => parseCose(hexToBytes('83010203')))).toMatch(/array of four items/);
        expect(failure(() => parseCose(hexToBytes('a0')))).toMatch(/array of four items/);
    });

    it('has another algorithm, none, or one that nothing signs', () => {
        expect(failure(() => parseCose(build(['8443a10126', 'a0', '4161', sig])))).toMatch(/ES256 \(-7\), only EdDSA/);
        expect(failure(() => parseCose(build(['8440', 'a0', '4161', sig])))).toMatch(/no algorithm/);
        expect(failure(() => parseCose(build(['8440', 'a10127', '4161', sig])))).toMatch(/unprotected header, which nothing signs/);
        expect(failure(() => parseCose(build(['8443a10199', 'a0', '4161', sig])))).not.toBe('no error');
    });

    it('has critical parameters, a parameter in both headers, or a wrong signature size', () => {
        expect(failure(() => parseCose(build(['8445a201270281', '01a0', '4161', sig].slice(0, 2).concat(['a0', '4161', sig]))))).not.toBe(
            'no error',
        );
        expect(failure(() => parseCose(build(['8444a1012702', 'a1', '0127', '4161', sig])))).not.toBe('no error');
        expect(failure(() => parseCose(build(['8443a10127', 'a10127', '4161', sig])))).toMatch(/both in the protected and the unprotected/);
        expect(failure(() => parseCose(build(['8443a10127', 'a0', '4161', '4101'])))).toMatch(/has 1 bytes/);
    });

    it('is cut short or is not CBOR', () => {
        expect(failure(() => parseCose(hexToBytes(COSE_PLAIN.slice(0, 40))))).toMatch(/Not a valid COSE message/);
        expect(failure(() => parseCose(hexToBytes(`${COSE_PLAIN}00`)))).toMatch(/after the CBOR item/);
        expect(failure(() => parseCose(new Uint8Array(0)))).toMatch(/cut short/);
    });
});

describe('the text of a message', () => {
    it('is hex (spaces and 0x allowed) or base64 / base64url', () => {
        const bytes = hexToBytes(COSE_PLAIN);
        expect(bytesToHex(bytesFromText(COSE_PLAIN))).toBe(COSE_PLAIN);
        expect(bytesToHex(bytesFromText(`0x${COSE_PLAIN.slice(0, 8)} ${COSE_PLAIN.slice(8)}`))).toBe(COSE_PLAIN);
        const base64 = Buffer.from(bytes).toString('base64');
        expect(bytesToHex(bytesFromText(base64))).toBe(COSE_PLAIN);
        expect(bytesToHex(bytesFromText(Buffer.from(bytes).toString('base64url')))).toBe(COSE_PLAIN);
        expect(failure(() => bytesFromText('hello world!'))).toMatch(/neither/);
        expect(failure(() => bytesFromText('  '))).toMatch(/empty/);
    });
});

describe('COSE_Key', () => {
    it('is written and read back, with the kid', () => {
        const key = encodeCoseKey(publicKey, text('11'));
        expect(parseCoseKey(key).publicKey).toEqual(publicKey);
        expect(bytesToHex(encodeCoseKey(publicKey))).toBe(COSE_KEY_HEX);
        expect(bytesToHex(readCoseKey(bytesToHex(key))?.kid as Uint8Array)).toBe('3131');
        expect(readCoseKey(Buffer.from(key).toString('base64'))?.publicKey).toEqual(publicKey);
    });

    it('is told apart from other keys', () => {
        expect(readCoseKey(COSE_PUBLIC)).toBeNull();
        expect(readCoseKey('ssh-ed25519 AAAA')).toBeNull();
        expect(readCoseKey('a1010101')).toBeNull(); // a map, but not a key
        expect(failure(() => parseCoseKey(hexToBytes('a201012007')))).toMatch(/crv 6/);
        expect(failure(() => parseCoseKey(hexToBytes('a201022001')))).toMatch(/OKP/);
    });

    it('the tag inside is not a map', () => {
        expect(decodeCbor(hexToBytes(COSE_ATTACHED))).toBeInstanceOf(Tagged);
    });
});

const check = async (signature: Uint8Array, data: Uint8Array, key: Uint8Array) =>
    (await ed.verifyAsync(signature, data, key, strict)) ? ('valid' as const) : ('invalid' as const);
const asSign = (hex: string) => {
    const parsed = parseCoseMessage(hexToBytes(hex));
    if (parsed.kind !== 'sign') throw new Error('not a COSE_Sign');
    return parsed;
};
const noAad = new Uint8Array(0);
const hello = text('hello world');

describe('a CWT: the claims', () => {
    it('reads the claims of RFC 8392 appendix A.3, by name, with the times', () => {
        const parsed = parseCose(hexToBytes(CWT_RFC8392));
        expect(parsed).toMatchObject({ cwt: true, tagged: true });
        expect(bytesToHex(parsed.payload as Uint8Array)).toBe(CWT_RFC8392_CLAIMS);
        const claims = readCwtClaims(parsed.payload as Uint8Array);
        expect(claims?.claims.map((claim) => claim.name)).toEqual([
            'iss (issuer)',
            'sub (subject)',
            'aud (audience)',
            'exp (expiration time)',
            'nbf (not before)',
            'iat (issued at)',
            'cti (CWT ID)',
        ]);
        expect(claims?.claims[0].value).toBe('coap://as.example.com');
        expect(claims).toMatchObject({ exp: 1444064944, nbf: 1443944944, iat: 1443944944, problems: [] });
    });

    it('the signature of the CWT verifies (made by pycose)', async () => {
        const parsed = parseCose(hexToBytes(CWT_RFC8392));
        const data = signedData(parsed.protectedBytes, parsed.payload as Uint8Array);
        expect(await ed.verifyAsync(parsed.signature, data, publicKey, strict)).toBe(true);
        expect(readCwtClaims(parseCose(hexToBytes(CWT_LONG)).payload as Uint8Array)).toMatchObject({ exp: 4102444800, iat: 1700000000 });
    });

    it('reads floats, unnamed and negative keys, and leaves a time that is not a number out of the checks', () => {
        const claims = readCwtClaims(parseCose(hexToBytes(COSE_MISC_CLAIMS)).payload as Uint8Array);
        expect(claims?.exp).toBe(4102444800.5);
        expect(claims?.claims.map((claim) => [claim.key, claim.name])).toEqual([
            [1, 'iss (issuer)'],
            [4, 'exp (expiration time)'],
            [6, 'iat (issued at)'], // a tag 1 around the number: not a plain number
            ['custom', null],
            [-70000, null],
        ]);
        expect(claims?.iat).toBeUndefined();
        expect(claims?.problems).toHaveLength(1);
        expect(claims?.problems[0]).toMatch(/iat is not a number/);
    });

    it('is not claims when the payload is a text, other CBOR, or a time no date can hold', () => {
        expect(readCwtClaims(text(COSE_MESSAGE))).toBeNull();
        expect(readCwtClaims(hexToBytes('83010203'))).toBeNull();
        expect(readCwtClaims(hexToBytes('a104fb4415af1d78b58c40'))?.problems).toHaveLength(1); // exp 1e16 seconds
        expect(readCwtClaims(hexToBytes('a0'))?.claims).toEqual([]);
    });
});

describe('COSE_Sign: reading', () => {
    it('reads the signatures of a message made by pycose, each with its kid', () => {
        const parsed = asSign(SIGN_THREE);
        expect(parsed).toMatchObject({ tagged: true, cwt: false });
        expect(new TextDecoder().decode(parsed.payload as Uint8Array)).toBe(COSE_MESSAGE);
        expect(parsed.signers).toHaveLength(3);
        expect(parsed.signers.map((signer) => (signer.kid ? new TextDecoder().decode(signer.kid) : null))).toEqual(['alice', 'bob', null]);
        expect(parsed.signers.every((signer) => signer.problem === undefined)).toBe(true);
    });

    it('reads one without the tag, and one inside a CWT tag', () => {
        const untagged = SIGN_TWO.slice(4); // without d862
        expect(parseCoseMessage(hexToBytes(untagged))).toMatchObject({ kind: 'sign', tagged: false });
        expect(parseCoseMessage(hexToBytes(`d83d${SIGN_TWO}`))).toMatchObject({ kind: 'sign', cwt: true });
        expect(parseCoseMessage(hexToBytes(COSE_PLAIN))).toMatchObject({ kind: 'sign1' });
    });

    it('is refused by parseCose, which reads COSE_Sign1 only', () => {
        expect(failure(() => parseCose(hexToBytes(SIGN_TWO)))).toMatch(/COSE_Sign: a message with several signatures, not a COSE_Sign1/);
    });

    it('keeps a signature it cannot check, with the reason, and refuses what is malformed', () => {
        const sig = `5840${'00'.repeat(64)}`;
        const message = (signers: string) => hexToBytes(`d8628440a0416182${signers}`);
        expect(parseCoseMessage(message(`8343a10126a0${sig}8343a10127a0${sig}`)) as unknown).toMatchObject({
            signers: [{ problem: expect.stringMatching(/ES256 \(-7\), only EdDSA/) }, { problem: undefined }],
        });
        expect(parseCoseMessage(message(`8340a0${sig}8343a10127a0${sig}`)) as unknown).toMatchObject({
            signers: [{ problem: expect.stringMatching(/no algorithm/) }, { problem: undefined }],
        });
        expect(parseCoseMessage(message(`8343a10127a0${'4101'}8343a10127a0${sig}`)) as unknown).toMatchObject({
            signers: [{ problem: expect.stringMatching(/has 1 bytes/) }, { problem: undefined }],
        });
        expect(failure(() => parseCoseMessage(hexToBytes('d8628440a0416180')))).toMatch(/no signature/);
        expect(failure(() => parseCoseMessage(hexToBytes('d8628440a0416140')))).toMatch(/CBOR array/);
        expect(failure(() => parseCoseMessage(hexToBytes('d8628440a04161818143a10127')))).toMatch(
            /Signature 1 is not a CBOR array of three items/,
        );
        expect(failure(() => parseCoseMessage(message(`8343a10127a10127${sig}8343a10127a0${sig}`)))).toMatch(
            /both in the protected and the unprotected/,
        );
        expect(failure(() => parseCoseMessage(hexToBytes('d86283')))).toMatch(/cut short|Not a valid/);
        expect(failure(() => parseCoseMessage(hexToBytes('d8628340a0f6')))).toMatch(/array of four items/);
    });

    it('refuses crit in the headers of the message', () => {
        const sig = `5840${'00'.repeat(64)}`;
        expect(failure(() => parseCoseMessage(hexToBytes(`d8628444a1028101a0416181${`8343a10127a0${sig}`}`)))).toMatch(/"crit"/);
    });
});

describe('COSE_Sign: verifying each signature', () => {
    const alice = { publicKey, kid: text('alice') };
    const bob = { publicKey: hexToBytes(COSE_PUBLIC_2), kid: text('bob') };

    it('two signatures by two keys made by pycose: both valid, by the key of their kid', async () => {
        const results = await verifySigners(asSign(SIGN_TWO), hello, noAad, [bob, alice], check);
        expect(results).toEqual([
            { verdict: 'valid', keyIndex: 1 },
            { verdict: 'valid', keyIndex: 0 },
        ]);
        expect(summarizeSigners(results)).toMatchObject({ valid: 2, total: 2, overall: 'valid' });
    });

    it('a signature whose key was not given is not checked, and the message is not valid', async () => {
        const results = await verifySigners(asSign(SIGN_THREE), hello, noAad, [alice, bob], check);
        expect(results.map((result) => result.verdict)).toEqual(['valid', 'valid', 'not-checked']);
        expect(results[2].reason).toMatch(/none of the 2 keys given verifies it/);
        expect(summarizeSigners(results)).toMatchObject({ valid: 2, notChecked: 1, overall: 'incomplete' });
    });

    it('a signature without a kid is tried with every key, so the key of the third signer makes the message valid', async () => {
        const third = { publicKey: hexToBytes(COSE_PUBLIC_3) };
        const results = await verifySigners(asSign(SIGN_THREE), hello, noAad, [alice, bob, third], check);
        expect(results).toEqual([
            { verdict: 'valid', keyIndex: 0 },
            { verdict: 'valid', keyIndex: 1 },
            { verdict: 'valid', keyIndex: 2 },
        ]);
    });

    it('only the keys given with a kid for the other signers: the signature with a kid and no key is not checked', async () => {
        const results = await verifySigners(asSign(SIGN_TWO), hello, noAad, [alice], check);
        expect(results).toEqual([
            { verdict: 'valid', keyIndex: 0 },
            { verdict: 'not-checked', reason: 'Not checked: no key was given for the key id "bob".' },
        ]);
        const summary = summarizeSigners(results);
        expect(summary).toMatchObject({ valid: 1, notChecked: 1, total: 2, overall: 'incomplete' });
        expect(summarizeSigners([{ verdict: 'not-checked' }]).overall).toBe('incomplete');
    });

    it('a key with no kid is tried for a signature that names one, when no key has that kid', async () => {
        const results = await verifySigners(asSign(SIGN_TWO), hello, noAad, [{ publicKey }, { publicKey: bob.publicKey }], check);
        expect(results.map((result) => result.verdict)).toEqual(['valid', 'valid']);
    });

    it('is wrong with the wrong key or the wrong payload, and the message is not valid', async () => {
        const wrongKey = await verifySigners(
            asSign(SIGN_TWO),
            hello,
            noAad,
            [{ publicKey: bob.publicKey, kid: text('alice') }, bob],
            check,
        );
        expect(wrongKey.map((result) => result.verdict)).toEqual(['invalid', 'valid']);
        expect(summarizeSigners(wrongKey).overall).toBe('invalid');
        const wrongPayload = await verifySigners(asSign(SIGN_TWO), text('hello world!'), noAad, [alice, bob], check);
        expect(wrongPayload.map((result) => result.verdict)).toEqual(['invalid', 'invalid']);
    });

    it('is invalid when one is wrong even if another was not checked', () => {
        expect(
            summarizeSigners([{ verdict: 'valid' }, { verdict: 'invalid' }, { verdict: 'not-checked' }, { verdict: 'permissive-only' }])
                .overall,
        ).toBe('invalid');
        expect(summarizeSigners([{ verdict: 'valid' }, { verdict: 'permissive-only' }]).overall).toBe('permissive-only');
    });

    it('covers the external data, and the payload given apart', async () => {
        const keys = [alice, bob];
        const verdicts = async (hex: string, payload: Uint8Array, aad: Uint8Array) =>
            (await verifySigners(asSign(hex), payload, aad, keys, check)).map((result) => result.verdict);
        expect(await verdicts(SIGN_TWO_AAD, hello, text('context'))).toEqual(['valid', 'valid']);
        expect(await verdicts(SIGN_TWO_AAD, hello, noAad)).toEqual(['invalid', 'invalid']);
        expect(asSign(SIGN_TWO_AAD_DETACHED).payload).toBeNull();
        expect(await verdicts(SIGN_TWO_AAD_DETACHED, hello, text('context'))).toEqual(['valid', 'valid']);
    });

    it('does not check the signature of an algorithm it does not know, and says why', async () => {
        const sig = `5840${'00'.repeat(64)}`;
        const parsed = asSign(`d8628440a0416181${`8343a10126a0${sig}`}`);
        const results = await verifySigners(parsed, text('a'), noAad, [alice], check);
        expect(results[0].verdict).toBe('not-checked');
        expect(results[0].reason).toMatch(/Not checked: its algorithm is ES256 \(-7\)/);
    });
});

describe('several keys', () => {
    it('reads a COSE_KeySet, in hex or base64', () => {
        const keys = readCoseKeys(COSE_KEYSET_AB);
        expect(keys?.map((key) => bytesToHex(key.publicKey as Uint8Array))).toEqual([COSE_PUBLIC, COSE_PUBLIC_2]);
        expect(keys?.map((key) => new TextDecoder().decode(key.kid))).toEqual(['alice', 'bob']);
        expect(readCoseKeys(Buffer.from(COSE_KEYSET_AB, 'hex').toString('base64'))).toHaveLength(2);
    });

    it('reads one key per line: COSE_Keys, or plain public keys', () => {
        expect(readCoseKeys(`${COSE_KEY_ALICE}\n${COSE_KEY_BOB}`)).toHaveLength(2);
        const mixed = readCoseKeys(`${COSE_KEY_ALICE}\n\n  ${COSE_PUBLIC_3}  \n${Buffer.from(COSE_PUBLIC_2, 'hex').toString('base64')}`);
        expect(mixed?.map((key) => key.kid !== undefined)).toEqual([true, false, false]);
        expect(bytesToHex(mixed?.[1].publicKey as Uint8Array)).toBe(COSE_PUBLIC_3);
    });

    it('a plain key that starts like a KeySet is still one key per line', () => {
        expect(readCoseKeys(`8a${COSE_PUBLIC_2.slice(2)}\n${COSE_PUBLIC_3}`)).toHaveLength(2);
    });

    it('is null for a single key in any format, and for lines that are not keys', () => {
        expect(readCoseKeys(COSE_PUBLIC)).toBeNull();
        expect(readCoseKeys(COSE_KEY_ALICE)).toBeNull();
        expect(readCoseKeys('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA\nsecond line')).toBeNull();
        expect(readCoseKeys(`${COSE_PUBLIC}\nnot a key`)).toBeNull();
        expect(readCoseKeys('')).toBeNull();
    });

    it('leaves the keys of other curves out of a KeySet, and refuses one with none of ours', () => {
        // [ {1: 2 (EC2), -1: 1, -2: x} ]
        expect(readCoseKeys(`81a301022001215820${'00'.repeat(32)}`)).toBeNull();
    });
});
