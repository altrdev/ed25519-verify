import VerifyEd25519, { generateKeyPair, InputError } from '../signature'
import {MessageFormat, SignEncoding} from "../enum";

const publicKey = "u6xMxXSXi/dL9tWPS+qfxiOHMA6c2Czwh/k2hy/wx/U=";
const base64Of = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

const signature = "BhqKbhnVH3kaNARj/Vht7ImJJ2LMM5TOla7k5OTITjdZ+GpWTY69wH79vRowPmq0c2KFDNipPsUcXSAwrviqDA==";

describe('Verify signature', function() {
    it('should return false with wrong signature', async () => {
        const sign = new VerifyEd25519("hello world!", signature, publicKey, null);
        const result = await sign.check();
        expect(result).toBe(false);
    })

    it('should return true with correct signature', async () => {
        const sign = new VerifyEd25519("000000102", signature, publicKey, null);
        const result = await sign.check();
        expect(result).toBe(true);
    })

    it('should accept base64 without padding, with the URL-safe alphabet and with line breaks', async () => {
        const urlSafe = signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const wrapped = `${urlSafe.slice(0, 40)}\n${urlSafe.slice(40)}`;
        const sign = new VerifyEd25519("000000102", wrapped, ` ${publicKey}\n`, null);
        expect(await sign.check()).toBe(true);
    })

    it('should reject malformed input instead of answering "wrong signature"', async () => {
        const sign = new VerifyEd25519("000000102", "dasdsad", "dasdasd", null);
        await expect(sign.check()).rejects.toBeInstanceOf(InputError);
    })

    it('should return false for a well formed public key that is not a point on the curve', async () => {
        const notAPoint = base64Of(new Uint8Array(32).fill(0xff));
        const sign = new VerifyEd25519("000000102", signature, notAPoint, null);
        expect(await sign.check()).toBe(false);
    })
})

describe('Input validation', function() {
    const validate = (fields: Partial<Record<'message' | 'signature' | 'publicKey' | 'privateKey', string>>, names: ('signature' | 'publicKey' | 'privateKey')[]) =>
        new VerifyEd25519(fields.message ?? '', fields.signature ?? null, fields.publicKey ?? null, fields.privateKey ?? null).validate(names);

    it('should report empty fields as required', () => {
        expect(validate({}, ['publicKey', 'signature'])).toEqual({
            publicKey: 'Public key is required.',
            signature: 'Signature is required.',
        });
    })

    it('should report text that is neither hex nor base64', () => {
        expect(validate({ signature: 'not base64!' }, ['signature']).signature).toBe('Signature is not valid hex or base64.');
        expect(validate({ publicKey: 'zz'.repeat(32) + '#' }, ['publicKey']).publicKey).toBe('Public key is not valid hex or base64.');
        expect(validate({ signature: 'G' }, ['signature']).signature).toBe('Signature is not valid hex or base64.');
        // 'A' is a hex digit: a lone one is an odd number of hex digits
        expect(validate({ signature: 'A' }, ['signature']).signature).toBe('Signature is not valid hex: it has an odd number of digits (1).');
    })

    it('should report the wrong length and say how the text was read', () => {
        const short = base64Of(new Uint8Array(31));
        expect(validate({ publicKey: short }, ['publicKey']).publicKey)
            .toBe('Public key: expected 32 bytes, got 31 (read as base64).');
        expect(validate({ privateKey: short }, ['privateKey']).privateKey)
            .toBe('Private key: expected 32 bytes (or 64 in NaCl format), got 31 (read as base64).');
        // hex digits only: read as hex, which is what a truncated hex key is
        expect(validate({ publicKey: 'ab'.repeat(31) }, ['publicKey']).publicKey)
            .toBe('Public key: expected 32 bytes, got 31 (read as hex).');
        expect(validate({ signature: 'cd'.repeat(65) }, ['signature']).signature)
            .toBe('Signature: expected 64 bytes, got 65 (read as hex).');
    })

    it('should read a truncated hex key as hex, not as an unpadded base64 key of another size', () => {
        // 43 hex digits would also decode as 32 bytes of base64, and 44 as 33: neither is what was meant
        expect(validate({ publicKey: 'ab'.repeat(22) }, ['publicKey']).publicKey)
            .toBe('Public key: expected 32 bytes, got 22 (read as hex).');
        expect(validate({ publicKey: 'a'.repeat(43) }, ['publicKey']).publicKey)
            .toBe('Public key is not valid hex: it has an odd number of digits (43).');
    })

    it('should call an odd number of hex digits by its name', () => {
        expect(validate({ publicKey: 'a'.repeat(63) }, ['publicKey']).publicKey)
            .toBe('Public key is not valid hex: it has an odd number of digits (63).');
    })

    it('should accept valid input', () => {
        expect(validate({ publicKey, signature }, ['publicKey', 'signature'])).toEqual({});
    })
})

describe('Hex or base64 is detected, not chosen', function() {
    const random = (length: number) => crypto.getRandomValues(new Uint8Array(length));
    const hexOf = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    const variantsOf = (bytes: Uint8Array) => {
        const padded = base64Of(bytes);
        return {
            hex: hexOf(bytes),
            HEX: hexOf(bytes).toUpperCase(),
            base64: padded,
            unpadded: padded.replace(/=+$/, ''),
            urlSafe: padded.replace(/\+/g, '-').replace(/\//g, '_'),
            wrapped: `${padded.slice(0, 20)}\n  ${padded.slice(20)}\n`,
        };
    };
    const errorsOf = (field: 'publicKey' | 'privateKey' | 'signature', value: string) =>
        new VerifyEd25519('', field === 'signature' ? value : null, field === 'publicKey' ? value : null, field === 'privateKey' ? value : null)
            .validate([field]);

    it.each([['publicKey', 32], ['signature', 64], ['privateKey', 32], ['privateKey', 64]] as const)(
        'accepts a %s of %i bytes in every way of writing it', (field, size) => {
            for (let i = 0; i < 100; i++) {
                for (const [name, text] of Object.entries(variantsOf(random(size)))) {
                    expect(errorsOf(field, text), `${field} as ${name}: ${text}`).toEqual({});
                }
            }
        });

    it('reads the same private key the same way whatever it is written in', async () => {
        const seed = random(32);
        const signatures = new Set<string>();
        for (const text of Object.values(variantsOf(seed))) {
            signatures.add(await new VerifyEd25519('same message', null, null, text).sign(SignEncoding.Hex));
        }
        expect(signatures.size).toBe(1);
    })

    it('can never read a text of hex digits as base64 by accident, whatever its length', () => {
        // hex digits are valid base64 characters too: the only place where the two readings could clash
        const limits = { publicKey: [64], signature: [128], privateKey: [64, 128] } as const;
        for (const [field, hexLengths] of Object.entries(limits) as [keyof typeof limits, readonly number[]][]) {
            for (let length = 1; length <= 200; length++) {
                const text = 'a1'.repeat(length).slice(0, length);   // hex digits only
                const accepted = Object.keys(errorsOf(field, text)).length === 0;
                expect(accepted, `${field}, ${length} hex digits`).toBe(hexLengths.includes(length));
            }
        }
    })

    it('accepts base64 only at the lengths of a valid size', () => {
        const limits = { publicKey: [43, 44], signature: [86, 88], privateKey: [43, 44, 86, 88] } as const;
        for (const [field, lengths] of Object.entries(limits) as [keyof typeof limits, readonly number[]][]) {
            for (let length = 1; length <= 200; length++) {
                const text = 'Zz+/'.repeat(length).slice(0, length);   // base64 characters outside the hex alphabet
                const accepted = Object.keys(errorsOf(field, text)).length === 0;
                // padding is optional, so a text of the right length with no '=' is valid when it ends on a full quantum
                if (accepted) expect(lengths, `${field}, ${length} characters`).toContain(length);
            }
        }
    })
})

describe('Sign message', function() {
    it('should reject with absent private key', async () => {
        const sign = new VerifyEd25519("hello world!", null, null, null);
        await expect(sign.sign(SignEncoding.Hex)).rejects.toMatchObject({ field: 'privateKey', message: 'Private key is required.' });
    })

    it('should reject with empty private key', async () => {
        const sign = new VerifyEd25519("hello world!", null, null, "");
        await expect(sign.sign(SignEncoding.Hex)).rejects.toBeInstanceOf(InputError);
    })

    it('should return signature with base64 private key', async () => {
        const sign = new VerifyEd25519("000000001", null, null, "Au+pr7EwTqpNEGOMkz3s5RnDnunOnhDYCT0hjueZIXo=");
        const result = await sign.sign(SignEncoding.Base64);
        expect(result).toBe("9as6qIjGsKt5L+m5vcJhMrN007oYMAQk4yUtZBeVQ3LRXWa99R2iStrXND9UWqkSeCfiKB55aO+aUYjMI6XvCQ==");
    })

    it('should return signature with hex private key', async () => {
        const sign = new VerifyEd25519("000000001", null, null, "02efa9afb1304eaa4d10638c933dece519c39ee9ce9e10d8093d218ee799217a");
        const result = await sign.sign(SignEncoding.Hex);
        expect(result).toBe("f5ab3aa888c6b0ab792fe9b9bdc26132b374d3ba18300424e3252d6417954372d15d66bdf51da24adad7343f545aa9127827e2281e7968ef9a5188cc23a5ef09");
    })

    // 64-byte (seed || public key) secret keys: the derived key must match the embedded public half
    it('should return public key', async () => {
        const sign = new VerifyEd25519("12345", null, null, "3WrwK5pNuYUbYeWeid1jr8+YJ5BIJ9bE5AoU7TpEXwERZ6w1rApJuqlpLg3Kjd7bYKonCPHScUS4Ufjrp8dRTg==");
        let result = await sign.getPublicKey(SignEncoding.Base64);
        expect(result).toBe("EWesNawKSbqpaS4Nyo3e22CqJwjx0nFEuFH466fHUU4=");
    })

    it('should reject the public key of a missing private key', async () => {
        const sign = new VerifyEd25519("12345", null, null, null);
        await expect(sign.getPublicKey(SignEncoding.Base64)).rejects.toBeInstanceOf(InputError);
    })
})

describe('Generate key pair', function() {
    it.each([SignEncoding.Hex, SignEncoding.Base64])('should generate a usable pair (%s)', async (encoding) => {
        const pair = await generateKeyPair(encoding);
        const signer = new VerifyEd25519("round trip", null, null, pair.privateKey);
        expect(await signer.getPublicKey(encoding)).toBe(pair.publicKey);

        const signed = await signer.sign(encoding);
        const verifier = new VerifyEd25519("round trip", signed, pair.publicKey, null);
        expect(await verifier.check()).toBe(true);
    })

    it('should generate a different pair every time', async () => {
        const a = await generateKeyPair(SignEncoding.Hex);
        const b = await generateKeyPair(SignEncoding.Hex);
        expect(a.privateKey).not.toBe(b.privateKey);
    })
})

describe('Message format', function() {
    const privateKey = "Au+pr7EwTqpNEGOMkz3s5RnDnunOnhDYCT0hjueZIXo=";

    it('should sign hex and base64 messages like the equivalent text', async () => {
        const text = await new VerifyEd25519("000000001", null, null, privateKey).sign(SignEncoding.Base64);
        const hex = await new VerifyEd25519("303030303030303031", null, null, privateKey, MessageFormat.Hex).sign(SignEncoding.Base64);
        const base64 = await new VerifyEd25519("MDAwMDAwMDAx", null, null, privateKey, MessageFormat.Base64).sign(SignEncoding.Base64);
        expect(hex).toBe(text);
        expect(base64).toBe(text);
    })

    it('should round trip binary data that is not valid UTF-8', async () => {
        const pair = await generateKeyPair(SignEncoding.Hex);
        const binary = "00ff80fe7f"; // 0x80 and 0xfe cannot be written as text
        const signed = await new VerifyEd25519(binary, null, null, pair.privateKey, MessageFormat.Hex).sign(SignEncoding.Hex);
        expect(await new VerifyEd25519(binary, signed, pair.publicKey, null, MessageFormat.Hex).check()).toBe(true);
        expect(await new VerifyEd25519("00ff80fe7e", signed, pair.publicKey, null, MessageFormat.Hex).check()).toBe(false);
    })

    it('should accept an empty message in every format', async () => {
        for (const format of [MessageFormat.Text, MessageFormat.Hex, MessageFormat.Base64]) {
            const signed = await new VerifyEd25519("", null, null, privateKey, format).sign(SignEncoding.Base64);
            expect(signed).toBe(await new VerifyEd25519("", null, null, privateKey).sign(SignEncoding.Base64));
        }
    })

    it('should tolerate whitespace and report malformed hex / base64 messages', async () => {
        const wrapped = new VerifyEd25519("3030 3030\n30303030 31", null, null, privateKey, MessageFormat.Hex);
        expect(await wrapped.sign(SignEncoding.Base64)).toBe(await new VerifyEd25519("000000001", null, null, privateKey).sign(SignEncoding.Base64));

        const bad = (message: string, format: MessageFormat) =>
            new VerifyEd25519(message, null, null, privateKey, format).validate(['message']).message;
        expect(bad("xyz", MessageFormat.Hex)).toBe('Message is not valid hex.');
        expect(bad("abc", MessageFormat.Hex)).toBe('Message is not valid hex.'); // odd number of digits
        expect(bad("not base64!", MessageFormat.Base64)).toBe('Message is not valid base64.');
        expect(bad("anything goes", MessageFormat.Text)).toBeUndefined();
        await expect(new VerifyEd25519("xyz", null, null, privateKey, MessageFormat.Hex).sign(SignEncoding.Base64))
            .rejects.toMatchObject({ field: 'message' });
    })
})

describe('Conformance', function() {
    // RFC 8032, section 7.1
    const vectors = [
        {
            name: 'TEST 1 (empty message)',
            privateKey: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
            publicKey: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
            message: '',
            signature: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        },
        {
            name: 'TEST 2 (one byte)',
            privateKey: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
            publicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
            message: '72',
            signature: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
        },
    ];

    it.each(vectors)('should match the RFC 8032 vector $name', async (v) => {
        const signer = new VerifyEd25519(v.message, null, null, v.privateKey, MessageFormat.Hex);
        expect(await signer.getPublicKey(SignEncoding.Hex)).toBe(v.publicKey);
        expect(await signer.sign(SignEncoding.Hex)).toBe(v.signature);
        const verifier = new VerifyEd25519(v.message, v.signature, v.publicKey, null, MessageFormat.Hex);
        expect(await verifier.check()).toBe(true);
    })

    // the identity point as public key and as R, S = 0: accepted by ZIP215 for ANY message, rejected by RFC 8032
    const identity = '01' + '00'.repeat(31);
    const trivialSignature = identity + '00'.repeat(32);

    it('should verify strictly: a small-order key with a trivial signature is not valid for an arbitrary message', async () => {
        const verifier = new VerifyEd25519("anything", trivialSignature, identity, null);
        expect(await verifier.check()).toBe(false);
    })

    it('should tell a signature that only the permissive ZIP215 rules accept from a wrong one', async () => {
        const trivial = new VerifyEd25519("anything", trivialSignature, identity, null);
        expect(await trivial.verdict()).toBe('permissive-only');

        const pair = await generateKeyPair(SignEncoding.Hex);
        const signed = await new VerifyEd25519("hello", null, null, pair.privateKey).sign(SignEncoding.Hex);
        expect(await new VerifyEd25519("hello", signed, pair.publicKey, null).verdict()).toBe('valid');
        expect(await new VerifyEd25519("hullo", signed, pair.publicKey, null).verdict()).toBe('invalid');
    })
})
