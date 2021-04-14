import VerifyEd25519 from '../signature'

const publicKey = "u6xMxXSXi/dL9tWPS+qfxiOHMA6c2Czwh/k2hy/wx/U=";
const signature = "BhqKbhnVH3kaNARj/Vht7ImJJ2LMM5TOla7k5OTITjdZ+GpWTY69wH79vRowPmq0c2KFDNipPsUcXSAwrviqDA==";

test('should return false with wrong signature', async () => {
    const sign = new VerifyEd25519("hello world!", signature, publicKey, null);
    const result = await sign.check();
    expect(result).toBe(false);
})

test('should return true with correct signature', async () => {
    const sign = new VerifyEd25519("000000102", signature, publicKey, null);
    const result = await sign.check();
    expect(result).toBe(true);
})

test('should return error if data are wrong', async () => {
    const sign = new VerifyEd25519("000000102", "dasdsad", "dasdasd", null);
    const result = await sign.check();
    expect(result).toBe(false);
})
