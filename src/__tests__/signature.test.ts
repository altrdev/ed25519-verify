import VerifyEd25519 from '../signature'
import {SignEncoding} from "../enum";

const publicKey = "u6xMxXSXi/dL9tWPS+qfxiOHMA6c2Czwh/k2hy/wx/U=";
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

    it('should return error if data are wrong', async () => {
        const sign = new VerifyEd25519("000000102", "dasdsad", "dasdasd", null);
        const result = await sign.check(SignEncoding.Base64);
        expect(result).toBe(false);
    })
})

describe('Sign message', function() {
    it('should return null with absent private key', async () => {
        const sign = new VerifyEd25519("hello world!", null, null, null);
        const result = await sign.sign(SignEncoding.Hex);
        expect(result).toBe(null);
    })

    it('should return null with empty private key', async () => {
        const sign = new VerifyEd25519("hello world!", null, null, "");
        const result = await sign.sign(SignEncoding.Hex);
        expect(result).toBe(null);
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

    it('should return public key', async () => {
        const sign = new VerifyEd25519("12345", null, null, "3WrwK5pNuYUbYeWeid1jr8+YJ5BIJ9bE5AoU7TpEXwERZ6w1rApJuqlpLg3Kjd7bYKonCPHScUS4Ufjrp8dRTg==");
        let result = await sign.getPublicKey(SignEncoding.Base64);
        expect(result).toBe("i78XoaMcWEnHUycO/hnRzsbqK5iGxFojkSYqw3GBFO8=");
    })

    it('should return null public key', async () => {
        const sign = new VerifyEd25519("12345", null, null, null);
        let result = await sign.getPublicKey(SignEncoding.Base64);
        expect(result).toBe(null);
    })
})
