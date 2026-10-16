import { hexToBytes } from '../bytes';
import { CborError, decodeCbor, encodeCbor, Tagged } from '../cbor';

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const decode = (text: string) => decodeCbor(hexToBytes(text.replace(/\s/g, '')));
const failure = (text: string) => {
    try {
        decode(text);
    } catch (e) {
        return e instanceof CborError ? e.message : `other: ${e}`;
    }
    return 'no error';
};

// the examples of RFC 8949, appendix A
describe('CBOR reader', () => {
    it.each([
        ['00', 0],
        ['17', 23],
        ['1818', 24],
        ['1903e8', 1000],
        ['1a000f4240', 1000000],
        ['20', -1],
        ['3863', -100],
        ['3903e7', -1000],
        ['f4', false],
        ['f5', true],
        ['f6', null],
        ['f7', undefined],
        ['f90000', 0],
        ['f93c00', 1],
        ['f9c400', -4],
        ['fa47c35000', 100000],
        ['fb3ff199999999999a', 1.1],
        ['6449455446', 'IETF'],
        ['62c3bc', 'ü'],
    ] as [string, unknown][])('reads %s', (text, expected) => {
        expect(decode(text)).toEqual(expected);
    });

    it('reads big integers, byte strings, arrays, maps and tags', () => {
        expect(decode('1bffffffffffffffff')).toBe(18446744073709551615n);
        expect(decode('3bffffffffffffffff')).toBe(-18446744073709551616n);
        expect(hex(decode('4401020304') as Uint8Array)).toBe('01020304');
        expect(decode('83010203')).toEqual([1, 2, 3]);
        expect(decode('a201020304')).toEqual(
            new Map<number, string | number>([
                [1, 2],
                [3, 4],
            ]),
        );
        expect(decode('a26161016162820203')).toEqual(
            new Map<string, unknown>([
                ['a', 1],
                ['b', [2, 3]],
            ]),
        );
        const tagged = decode('c074323031332d30332d32315432303a30343a30305a') as Tagged;
        expect(tagged).toBeInstanceOf(Tagged);
        expect(tagged.tag).toBe(0);
        expect(tagged.value).toBe('2013-03-21T20:04:00Z');
    });

    it.each([
        ['', /cut short/],
        ['18', /cut short/],
        ['4401', /cut short/],
        ['8301', /cut short/],
        ['5bffffffffffffffff', /cut short/],
        ['9f01ff', /Indefinite/],
        ['5f4101ff', /Indefinite/],
        ['a201020103', /twice/],
        ['a1f401', /neither an integer nor a text/],
        ['0000', /after the CBOR item/],
        ['62c328', /UTF-8/],
        ['fc', /simple value/],
        ['1c', /not valid CBOR/],
        ['f0', /simple value/],
    ])('refuses %s', (text, expected) => {
        expect(failure(text)).toMatch(expected);
    });

    it('refuses nesting that is too deep, and a count that is a lie (no huge loop)', () => {
        expect(failure(`${'81'.repeat(40)}00`)).toMatch(/too deeply/);
        expect(failure('9affffffff')).toMatch(/cut short/);
    });
});

describe('CBOR writer', () => {
    it.each([
        [0, '00'],
        [23, '17'],
        [24, '1818'],
        [255, '18ff'],
        [256, '190100'],
        [65536, '1a00010000'],
        [-1, '20'],
        [-8, '27'],
        [-19, '32'],
        [-25, '3818'],
        [-1000, '3903e7'],
    ])('writes the integer %i shortest', (value, expected) => {
        expect(hex(encodeCbor(value))).toBe(expected);
    });

    it('writes strings, arrays, maps, tags and the simple values', () => {
        expect(hex(encodeCbor('IETF'))).toBe('6449455446');
        expect(hex(encodeCbor(Uint8Array.of(1, 2)))).toBe('420102');
        expect(hex(encodeCbor([1, [2, 3], null, true]))).toBe('8301820203f6f5'.replace('83', '84'));
        expect(
            hex(
                encodeCbor(
                    new Map<number, string | number>([
                        [1, 2],
                        [-1, 'a'],
                    ]),
                ),
            ),
        ).toBe('a201022061 61'.replace(' ', ''));
        expect(hex(encodeCbor(new Tagged(18, [1])))).toBe('d28101');
    });

    it('reads back what it writes', () => {
        const value = new Map<number | string, unknown>([
            [1, -8],
            [4, Uint8Array.of(9)],
            ['x', [true, null, 'é']],
        ]);
        expect(decodeCbor(encodeCbor(value as never))).toEqual(value);
    });
});
