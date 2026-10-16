/**
 * BLAKE2b (RFC 7693), needed for minisign: its "ED" signatures sign the BLAKE2b-512 hash of the message. WebCrypto has no BLAKE2,
 * so this is a small implementation on 32-bit halves (a message can be up to 100 MB, which BigInt would take minutes to hash).
 * Unkeyed only. Checked against Python's hashlib.blake2b and the RFC's vector in the tests.
 */
const IV = [
    0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1, 0x510e527f, 0xade682d1, 0x9b05688c,
    0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
]; // eight 64-bit words as (high, low) pairs

const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// the working vector v and the message block m hold 64-bit words as [low, high] pairs of 32 bits
const v = new Uint32Array(32);
const m = new Uint32Array(32);

/** v[a] += v[b] + m[x] (64-bit, wrapping) */
function add3(a: number, b: number, x: number) {
    const lo = v[2 * a] + v[2 * b] + m[2 * x];
    const carry = Math.floor(lo / 0x100000000);
    v[2 * a] = lo;
    v[2 * a + 1] = v[2 * a + 1] + v[2 * b + 1] + m[2 * x + 1] + carry;
}
function add2(a: number, b: number) {
    const lo = v[2 * a] + v[2 * b];
    const carry = lo > 0xffffffff ? 1 : 0;
    v[2 * a] = lo;
    v[2 * a + 1] = v[2 * a + 1] + v[2 * b + 1] + carry;
}
/** v[d] = rotr64(v[d] ^ v[a], n) */
function xorRot(d: number, a: number, n: number) {
    const lo = v[2 * d] ^ v[2 * a];
    const hi = v[2 * d + 1] ^ v[2 * a + 1];
    if (n === 32) {
        v[2 * d] = hi;
        v[2 * d + 1] = lo;
    } else if (n < 32) {
        v[2 * d] = (lo >>> n) | (hi << (32 - n));
        v[2 * d + 1] = (hi >>> n) | (lo << (32 - n));
    } else {
        const k = n - 32; // rotating by 32 + k: swap the halves, then rotate by k
        v[2 * d] = (hi >>> k) | (lo << (32 - k));
        v[2 * d + 1] = (lo >>> k) | (hi << (32 - k));
    }
}
function g(a: number, b: number, c: number, d: number, x: number, y: number) {
    add3(a, b, x);
    xorRot(d, a, 32);
    add2(c, d);
    xorRot(b, c, 24);
    add3(a, b, y);
    xorRot(d, a, 16);
    add2(c, d);
    xorRot(b, c, 63);
}

/** BLAKE2b-512 of `data`. */
export function blake2b512(data: Uint8Array): Uint8Array {
    const h = new Uint32Array(16);
    for (let i = 0; i < 8; i++) {
        h[2 * i] = IV[2 * i + 1];
        h[2 * i + 1] = IV[2 * i];
    }
    h[0] ^= 0x01010000 ^ 64; // no key, sequential mode, 64 bytes of output
    const blocks = Math.max(1, Math.ceil(data.length / 128));
    const block = new Uint8Array(128);
    for (let n = 0; n < blocks; n++) {
        const last = n === blocks - 1;
        const start = n * 128;
        block.fill(0);
        block.set(data.subarray(start, Math.min(start + 128, data.length)));
        const view = new DataView(block.buffer);
        for (let i = 0; i < 32; i++) m[i] = view.getUint32(i * 4, true);
        const counter = last ? data.length : start + 128; // bytes hashed so far, this block included (below 2^53)
        for (let i = 0; i < 16; i++) v[i] = h[i];
        for (let i = 0; i < 8; i++) {
            v[16 + 2 * i] = IV[2 * i + 1];
            v[17 + 2 * i] = IV[2 * i];
        }
        v[24] ^= counter;
        v[25] ^= Math.floor(counter / 0x100000000);
        if (last) {
            v[28] = ~v[28];
            v[29] = ~v[29];
        }
        for (let round = 0; round < 12; round++) {
            const s = SIGMA[round % 10];
            g(0, 4, 8, 12, s[0], s[1]);
            g(1, 5, 9, 13, s[2], s[3]);
            g(2, 6, 10, 14, s[4], s[5]);
            g(3, 7, 11, 15, s[6], s[7]);
            g(0, 5, 10, 15, s[8], s[9]);
            g(1, 6, 11, 12, s[10], s[11]);
            g(2, 7, 8, 13, s[12], s[13]);
            g(3, 4, 9, 14, s[14], s[15]);
        }
        for (let i = 0; i < 16; i++) h[i] ^= v[i] ^ v[i + 16];
    }
    const out = new Uint8Array(64);
    const view = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) view.setUint32(i * 4, h[i], true);
    return out;
}
