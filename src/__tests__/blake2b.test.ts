import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { blake2b512 } from '../blake2b';

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const reference = (data: Uint8Array) => createHash('blake2b512').update(data).digest('hex');

describe('BLAKE2b-512', () => {
    it('matches the vector of RFC 7693 (abc)', () => {
        expect(hex(blake2b512(new TextEncoder().encode('abc')))).toBe(
            'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
        );
    });

    it('matches OpenSSL around every block boundary, and for random data', () => {
        for (const length of [0, 1, 2, 63, 64, 127, 128, 129, 255, 256, 257, 383, 384, 385, 1000, 4096, 100001]) {
            const data = new Uint8Array(randomBytes(length));
            expect(hex(blake2b512(data)), `length ${length}`).toBe(reference(data));
        }
    });

    it('handles bytes that make every carry and rotation matter', () => {
        for (const fill of [0x00, 0xff, 0x80, 0x01]) {
            const data = new Uint8Array(777).fill(fill);
            expect(hex(blake2b512(data))).toBe(reference(data));
        }
    });

    it('hashes a megabyte quickly enough for a big file', () => {
        const data = new Uint8Array(randomBytes(8 * 1024 * 1024));
        const start = performance.now();
        expect(hex(blake2b512(data))).toBe(reference(data));
        expect(performance.now() - start).toBeLessThan(5000);
    });
});
