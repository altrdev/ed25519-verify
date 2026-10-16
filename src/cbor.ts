/**
 * A small CBOR (RFC 8949) reader and writer, enough for COSE: integers, byte and text strings, arrays, maps, tags and the simple
 * values. The reader refuses what COSE has no use for and what is easy to abuse: indefinite lengths, duplicate map keys, lengths
 * that run past the data, deep nesting. Pure functions, no dependencies.
 */
export class CborError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'CborError';
    }
}

export class Tagged {
    constructor(
        readonly tag: number,
        readonly value: CborValue,
    ) {}
}

export type CborValue = number | bigint | boolean | null | undefined | string | Uint8Array | CborValue[] | Map<CborKey, CborValue> | Tagged;
/** map keys are integers or strings (COSE uses nothing else) */
export type CborKey = number | string;

/** Bytes, whatever realm they come from (an iframe, a test environment): `instanceof Uint8Array` is not enough. */
export const isBytes = (value: unknown): value is Uint8Array => ArrayBuffer.isView(value) && !(value instanceof DataView);

const MAX_DEPTH = 16;
const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

class Reader {
    pos = 0;
    constructor(readonly data: Uint8Array) {}

    need(length: number) {
        if (length > this.data.length - this.pos) throw new CborError('The data is cut short: a length runs past its end.');
    }
    byte(): number {
        this.need(1);
        return this.data[this.pos++];
    }
    take(length: number): Uint8Array {
        this.need(length);
        const value = this.data.slice(this.pos, this.pos + length);
        this.pos += length;
        return value;
    }
    /** the argument that follows the initial byte */
    argument(info: number): number | bigint {
        if (info < 24) return info;
        const size = [1, 2, 4, 8][info - 24];
        if (size === undefined)
            throw new CborError(info === 31 ? 'Indefinite-length items are not supported.' : 'The data is not valid CBOR.');
        const bytes = this.take(size);
        let value = 0n;
        for (const b of bytes) value = (value << 8n) | BigInt(b);
        return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
    }
    count(info: number): number {
        const length = this.argument(info);
        // an item is at least one byte: a longer count than the data left is a lie, and would be a huge loop
        if (typeof length === 'bigint' || length > this.data.length - this.pos)
            throw new CborError('The data is cut short: a length runs past its end.');
        return length;
    }

    item(depth: number): CborValue {
        if (depth > MAX_DEPTH) throw new CborError('The data is nested too deeply.');
        const initial = this.byte();
        const major = initial >> 5;
        const info = initial & 31;
        switch (major) {
            case 0:
                return this.argument(info);
            case 1: {
                const n = this.argument(info);
                return typeof n === 'bigint' ? -1n - n : -1 - n;
            }
            case 2:
                return this.take(this.count(info));
            case 3: {
                try {
                    return decoder.decode(this.take(this.count(info)));
                } catch (error) {
                    if (error instanceof CborError) throw error;
                    throw new CborError('A text string is not valid UTF-8.');
                }
            }
            case 4: {
                const length = this.count(info);
                return Array.from({ length }, () => this.item(depth + 1));
            }
            case 5: {
                const length = this.count(info);
                const map = new Map<CborKey, CborValue>();
                for (let i = 0; i < length; i++) {
                    const key = this.item(depth + 1);
                    if (typeof key !== 'number' && typeof key !== 'string')
                        throw new CborError('A map key is neither an integer nor a text.');
                    if (map.has(key)) throw new CborError(`The map has the key ${JSON.stringify(key)} twice.`);
                    map.set(key, this.item(depth + 1));
                }
                return map;
            }
            case 6: {
                const tag = this.argument(info);
                if (typeof tag === 'bigint') throw new CborError('A tag number is too large.');
                return new Tagged(tag, this.item(depth + 1));
            }
            default: {
                if (info === 20) return false;
                if (info === 21) return true;
                if (info === 22) return null;
                if (info === 23) return undefined;
                if (info === 25 || info === 26 || info === 27) {
                    const bytes = this.take(2 ** (info - 24));
                    const view = new DataView(bytes.buffer);
                    if (info === 26) return view.getFloat32(0);
                    if (info === 27) return view.getFloat64(0);
                    const half = view.getUint16(0);
                    const exponent = (half >> 10) & 31;
                    const fraction = half & 1023;
                    const magnitude =
                        exponent === 0
                            ? fraction * 2 ** -24
                            : exponent === 31
                              ? fraction
                                  ? Number.NaN
                                  : Number.POSITIVE_INFINITY
                              : (1 + fraction / 1024) * 2 ** (exponent - 15);
                    return half & 0x8000 ? -magnitude : magnitude;
                }
                throw new CborError('The data holds a simple value that COSE does not use.');
            }
        }
    }
}

/** Reads one CBOR item, which must be all of the data. */
export function decodeCbor(data: Uint8Array): CborValue {
    const reader = new Reader(data);
    const value = reader.item(0);
    if (reader.pos !== data.length) throw new CborError('There is data after the CBOR item.');
    return value;
}

const head = (major: number, value: number): Uint8Array => {
    if (value < 24) return Uint8Array.of((major << 5) | value);
    if (value < 0x100) return Uint8Array.of((major << 5) | 24, value);
    if (value < 0x10000) return Uint8Array.of((major << 5) | 25, value >> 8, value & 255);
    return Uint8Array.of((major << 5) | 26, (value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
};

const concat = (...parts: Uint8Array[]): Uint8Array => {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
};

/** Writes a value in its shortest form (the maps in the order they have). Integers must be safe and below 2^32 in size. */
export function encodeCbor(value: CborValue): Uint8Array {
    if (value === null) return Uint8Array.of(0xf6);
    if (value === undefined) return Uint8Array.of(0xf7);
    if (typeof value === 'boolean') return Uint8Array.of(value ? 0xf5 : 0xf4);
    if (typeof value === 'number') {
        if (!Number.isInteger(value) || Math.abs(value) > 0xffffffff) throw new CborError('Only integers up to 32 bits can be written.');
        return value >= 0 ? head(0, value) : head(1, -1 - value);
    }
    if (typeof value === 'bigint') throw new CborError('Only integers up to 32 bits can be written.');
    if (typeof value === 'string') {
        const bytes = encoder.encode(value);
        return concat(head(3, bytes.length), bytes);
    }
    if (isBytes(value)) return concat(head(2, value.length), value);
    if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(encodeCbor));
    if (value instanceof Map) return concat(head(5, value.size), ...Array.from(value, ([k, v]) => concat(encodeCbor(k), encodeCbor(v))));
    return concat(head(6, value.tag), encodeCbor(value.value));
}
