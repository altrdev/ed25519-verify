import { bytesToHex, hexToBytes } from '../bytes';
import { CODECS, decodeBase32, decodeBase58, decodeByteArray, encodeAs, encodeBase32, encodeBase58, readings } from '../codecs';
import type { RawFormat } from '../enum';

const FORMATS = Object.keys(CODECS) as RawFormat[];
const random = (length: number) => crypto.getRandomValues(new Uint8Array(length));
const hex = (bytes: Uint8Array | null) => (bytes ? bytesToHex(bytes) : null);

describe('base58', () => {
    // Bitcoin's reference vectors, confirmed with an independent implementation (Python base58)
    const VECTORS: [string, string][] = [
        ['', ''],
        ['61', '2g'],
        ['626262', 'a3gV'],
        ['636363', 'aPEr'],
        ['73696d706c792061206c6f6e6720737472696e67', '2cFupjhnEsSn59qHXstmK2ffpLv2'],
        ['00eb15231dfceb60925886b67d065299925915aeb172c06647', '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L'],
        ['516b6fcd0f', 'ABnLTmg'],
        ['bf4f89001e670274dd', '3SEo3LWLoPntC'],
        ['572e4794', '3EFU7m'],
        ['ecac89cad93923c02321', 'EJDM8drfXA6uyA'],
        ['10c8511e', 'Rt5zm'],
        ['00000000000000000000', '1111111111'],
    ];

    it.each(VECTORS)('encodes and decodes %s', (hexValue, text) => {
        expect(encodeBase58(hexToBytes(hexValue))).toBe(text);
        expect(hex(decodeBase58(text))).toBe(hexValue);
    });

    it('matches the Solana addresses everybody knows', () => {
        expect(hex(decodeBase58('11111111111111111111111111111111'))).toBe('00'.repeat(32)); // System Program
        expect(hex(decodeBase58('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'))).toBe(
            '06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9',
        ); // Token Program
    });

    it('rejects characters outside the alphabet (0, O, I, l, +, /)', () => {
        for (const bad of ['0', 'O', 'I', 'l', 'ab+c', 'ab/c', 'ab=c', 'ab c']) expect(decodeBase58(bad)).toBeNull();
    });
});

describe('base32', () => {
    // RFC 4648, section 10
    const VECTORS: [string, string][] = [
        ['', ''],
        ['f', 'MY======'],
        ['fo', 'MZXQ===='],
        ['foo', 'MZXW6==='],
        ['foob', 'MZXW6YQ='],
        ['fooba', 'MZXW6YTB'],
        ['foobar', 'MZXW6YTBOI======'],
    ];

    it.each(VECTORS)('encodes and decodes "%s"', (plain, padded) => {
        const bytes = new TextEncoder().encode(plain);
        expect(encodeBase32(bytes, true)).toBe(padded);
        expect(encodeBase32(bytes)).toBe(padded.replace(/=+$/, ''));
        if (plain) {
            expect(hex(decodeBase32(padded))).toBe(bytesToHex(bytes));
            expect(hex(decodeBase32(padded.replace(/=+$/, '')))).toBe(bytesToHex(bytes));
            expect(hex(decodeBase32(padded.replace(/=+$/, '').toLowerCase()))).toBe(bytesToHex(bytes));
        }
    });

    it('rejects what is not base32', () => {
        for (const bad of ['', 'MZXW6YT0', 'MZXW6YT1', 'MzXW6YTB', 'M', 'MZX', 'MZXW6YTBO', 'MZXW6YTBOI#']) {
            expect(decodeBase32(bad), bad).toBeNull();
        }
        // leftover bits must be zero: "MZ" is not a valid encoding of a single byte
        expect(decodeBase32('MZ')).toBeNull();
    });
});

describe('byte arrays', () => {
    it('reads the notations other tools print', () => {
        expect(hex(decodeByteArray('[1, 2, 255]'))).toBe('0102ff');
        expect(hex(decodeByteArray('[1,2,255]'))).toBe('0102ff');
        expect(hex(decodeByteArray('  [\n  1,\n  2,\n  255\n]  '))).toBe('0102ff');
        expect(hex(decodeByteArray('{0x01, 0x02, 0xff}'))).toBe('0102ff');
        expect(hex(decodeByteArray('[0x1, 2, 0XFF]'))).toBe('0102ff');
    });

    it('rejects anything else', () => {
        for (const bad of ['', '[]', '[256]', '[-1]', '[1.5]', '["a"]', '[1, 2', '1, 2, 3', '[1 2 x]', '[0x100]']) {
            expect(decodeByteArray(bad), bad).toBeNull();
        }
    });
});

describe('every codec', () => {
    it.each(FORMATS)('writes and reads back %s, for any length', (format) => {
        for (let length = 1; length <= 70; length++) {
            for (let i = 0; i < 5; i++) {
                const bytes = random(length);
                const text = encodeAs(bytes, format);
                expect(hex(CODECS[format].decode(text)), `${format}, ${length} bytes: ${text}`).toBe(bytesToHex(bytes));
            }
        }
    });

    it.each(FORMATS)('keeps leading zero bytes in %s', (format) => {
        for (const zeros of [1, 2, 5]) {
            const bytes = Uint8Array.from([...new Array<number>(zeros).fill(0), 7, 8, 9]);
            expect(hex(CODECS[format].decode(encodeAs(bytes, format)))).toBe(bytesToHex(bytes));
        }
    });

    it('writes the formats the way the ecosystems expect them', () => {
        const bytes = Uint8Array.from([0, 255, 16]);
        expect(encodeAs(bytes, 'hex')).toBe('00ff10');
        expect(encodeAs(bytes, 'hex0x')).toBe('0x00ff10');
        expect(encodeAs(bytes, 'base64')).toBe('AP8Q');
        expect(encodeAs(Uint8Array.from([251, 255, 254, 1]), 'base64')).toBe('+//+AQ==');
        expect(encodeAs(Uint8Array.from([251, 255, 254, 1]), 'base64url')).toBe('-__-AQ'); // URL-safe, no padding
        expect(encodeAs(bytes, 'bytes')).toBe('[0, 255, 16]');
    });
});

describe('readings of a pasted text', () => {
    const formatsOf = (text: string) => readings(text).map((r) => r.format);

    it('recognises the notations that cannot be mistaken', () => {
        expect(formatsOf('[1, 2, 3]')).toEqual(['bytes']);
        expect(formatsOf('{0x01, 0x02}')).toEqual(['bytes']);
        expect(formatsOf('0x00ff10')).toEqual(['hex0x']);
        expect(formatsOf('00ff10')).toEqual(['hex']);
        expect(formatsOf('00FF10')).toEqual(['hex']);
        expect(formatsOf('00ff 10\n')).toEqual(['hex']); // whitespace from a paste
    });

    it('reads a text made of hex digits only as hex, even when it would also be valid base64 or base58', () => {
        expect(formatsOf('a1'.repeat(22))).toEqual(['hex']);
        expect(readings('a'.repeat(43))).toEqual([]); // odd number of digits: hex is the only reading and it fails
    });

    it('offers every reading that decodes when the text could be several things', () => {
        // 43 characters of the base58 alphabet, not hex only: valid base64 (unpadded) and valid base58
        const text = 'Gjy4uRbVRBZ6zUpDEvKLxzFrWmGB6qYTa9qBBSgqLLd';
        expect(formatsOf(text)).toEqual(['base64', 'base58']);
        // a character that only base64 has settles it
        expect(formatsOf('Gjy4uRbVRBZ6zUpDEvKLxzFrWmGB6qYTa9qBBSgqL+d')).toEqual(['base64']);
        expect(formatsOf('Gjy4uRbVRBZ6zUpDEvKLxzFrWmGB6qYTa9qBBSgqL-d')).toEqual(['base64url']);
        // base58 has no 0, O, I or l
        expect(formatsOf('Gjy4uRbVRBZ6zUpDEvKLxzFrWmGB6qYTa9qBBSgqLOd')).toEqual(['base64']);
    });

    it('does not take a base64 text that begins with 0x or 0X for a hex number', () => {
        // found by the random tests: about 1 key in 2000 starts with these two characters
        expect(formatsOf('0XT4oL5MnkBEhIYUrMGRqOD7IQzkyBETeTslubcTYBc=')).toEqual(['base64']);
        // the first bytes 0xd3 0x1c are written "0x" in base64 (built here, not typed by hand)
        const lower = CODECS.base64.encode(Uint8Array.from([0xd3, 0x1c, ...new Array<number>(30).fill(7)]));
        expect(lower.slice(0, 2)).toBe('0x');
        expect(formatsOf(lower)).toEqual(['base64']);
        // while a real 0x number stays one, and a 0x text that is not hex falls through to the other readings
        expect(formatsOf('0xAAAA')).toEqual(['hex0x']);
        expect(formatsOf('0x00ff10')).toEqual(['hex0x']);
    });

    it('finds nothing in text that is not a recognised notation', () => {
        for (const bad of ['', '!!!', 'hello world!', '[1, 2', 'ab+c=d']) expect(readings(bad), bad).toEqual([]);
    });
});
