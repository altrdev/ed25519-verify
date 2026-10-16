import VerifyEd25519, { generateKeyPair, InputError } from '../signature'
import {MessageFormat, SignEncoding} from "../enum";

const publicKey = "u6xMxXSXi/dL9tWPS+qfxiOHMA6c2Czwh/k2hy/wx/U=";
const base64Of = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

const signature = "BhqKbhnVH3kaNARj/Vht7ImJJ2LMM5TOla7k5OTITjdZ+GpWTY69wH79vRowPmq0c2KFDNipPsUcXSAwrviqDA==";

describe('Verify signature', function() {
    it('should return false with wrong signature', async () => {
        const sign = new VerifyEd25519("hello world!", signature, publicKey, null);
        const result = await sign.check(SignEncoding.Base64);
        expect(result).toBe(false);
    })

    it('should return true with correct signature', async () => {
        const sign = new VerifyEd25519("000000102", signature, publicKey, null);
        const result = await sign.check(SignEncoding.Base64);
        expect(result).toBe(true);
    })

    it('should accept base64 without padding, with the URL-safe alphabet and with line breaks', async () => {
        const urlSafe = signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const wrapped = `${urlSafe.slice(0, 40)}\n${urlSafe.slice(40)}`;
        const sign = new VerifyEd25519("000000102", wrapped, ` ${publicKey}\n`, null);
        expect(await sign.check(SignEncoding.Base64)).toBe(true);
    })

    it('should reject malformed input instead of answering "wrong signature"', async () => {
        const sign = new VerifyEd25519("000000102", "dasdsad", "dasdasd", null);
        await expect(sign.check(SignEncoding.Base64)).rejects.toBeInstanceOf(InputError);
    })

    it('should return false for a well formed public key that is not a point on the curve', async () => {
        const notAPoint = base64Of(new Uint8Array(32).fill(0xff));
        const sign = new VerifyEd25519("000000102", signature, notAPoint, null);
        expect(await sign.check(SignEncoding.Base64)).toBe(false);
    })
})

describe('Input validation', function() {
    const validate = (fields: Partial<Record<'message' | 'signature' | 'publicKey' | 'privateKey', string>>, enc: SignEncoding, names: ('signature' | 'publicKey' | 'privateKey')[]) =>
        new VerifyEd25519(fields.message ?? '', fields.signature ?? null, fields.publicKey ?? null, fields.privateKey ?? null).validate(enc, names);

    it('should report empty fields as required', () => {
        expect(validate({}, SignEncoding.Base64, ['publicKey', 'signature'])).toEqual({
            publicKey: 'Public key is required.',
            signature: 'Signature is required.',
        });
    })

    it('should report invalid characters and odd length in hex', () => {
        expect(validate({ publicKey: 'zz'.repeat(32) }, SignEncoding.Hex, ['publicKey']).publicKey).toBe('Public key is not valid hex.');
        expect(validate({ publicKey: 'a'.repeat(63) }, SignEncoding.Hex, ['publicKey']).publicKey).toBe('Public key is not valid hex.');
    })

    it('should report invalid base64', () => {
        expect(validate({ signature: 'not base64!' }, SignEncoding.Base64, ['signature']).signature).toBe('Signature is not valid base64.');
        expect(validate({ signature: 'A' }, SignEncoding.Base64, ['signature']).signature).toBe('Signature is not valid base64.');
    })

    it('should report the wrong length, with the expected one', () => {
        const short = base64Of(new Uint8Array(31));
        expect(validate({ publicKey: short }, SignEncoding.Base64, ['publicKey']).publicKey)
            .toBe('Public key: expected 32 bytes, got 31.');
        expect(validate({ privateKey: short }, SignEncoding.Base64, ['privateKey']).privateKey)
            .toBe('Private key: expected 32 bytes (or 64 in NaCl format), got 31.');
    })

    it('should hint at the encoding when the data would be valid in the other one', () => {
        const hexKey = "02efa9afb1304eaa4d10638c933dece519c39ee9ce9e10d8093d218ee799217a";
        expect(validate({ privateKey: hexKey }, SignEncoding.Base64, ['privateKey']).privateKey)
            .toContain('It looks like hex: switch the encoding.');
        const b64Key = "Au+pr7EwTqpNEGOMkz3s5RnDnunOnhDYCT0hjueZIXo=";
        expect(validate({ privateKey: b64Key }, SignEncoding.Hex, ['privateKey']).privateKey)
            .toBe('Private key is not valid hex.');
    })

    it('should accept valid input', () => {
        expect(validate({ publicKey, signature }, SignEncoding.Base64, ['publicKey', 'signature'])).toEqual({});
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
        expect(await verifier.check(encoding)).toBe(true);
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
        expect(await new VerifyEd25519(binary, signed, pair.publicKey, null, MessageFormat.Hex).check(SignEncoding.Hex)).toBe(true);
        expect(await new VerifyEd25519("00ff80fe7e", signed, pair.publicKey, null, MessageFormat.Hex).check(SignEncoding.Hex)).toBe(false);
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
            new VerifyEd25519(message, null, null, privateKey, format).validate(SignEncoding.Base64, ['message']).message;
        expect(bad("xyz", MessageFormat.Hex)).toBe('Message is not valid hex.');
        expect(bad("abc", MessageFormat.Hex)).toBe('Message is not valid hex.'); // odd number of digits
        expect(bad("not base64!", MessageFormat.Base64)).toBe('Message is not valid base64.');
        expect(bad("anything goes", MessageFormat.Text)).toBeUndefined();
        await expect(new VerifyEd25519("xyz", null, null, privateKey, MessageFormat.Hex).sign(SignEncoding.Base64))
            .rejects.toMatchObject({ field: 'message' });
    })
})
