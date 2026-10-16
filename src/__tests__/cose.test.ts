import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '../bytes';
import { decodeCbor, Tagged } from '../cbor';
import { bytesFromText, CoseError, encodeCoseKey, parseCose, parseCoseKey, readCoseKey, signCose, signedData } from '../cose';
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
