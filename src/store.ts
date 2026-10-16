import { signal, effect } from '@preact/signals';
import { CODECS } from './codecs';
import type { RawFormat } from './enum';

export type Theme = 'light' | 'dark';

function read(key: string): string | null {
    try {
        return localStorage.getItem(key);
    } catch {
        return null;
    }
}

function write(key: string, value: string) {
    try {
        localStorage.setItem(key, value);
    } catch {
        // storage unavailable (private mode, blocked): the preference is just not persisted
    }
}

const storedTheme = read('theme');
const prefersDark = typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches;

export const theme = signal<Theme>(storedTheme === 'dark' || (storedTheme === null && prefersDark) ? 'dark' : 'light');

effect(() => {
    write('theme', theme.value);
    document.documentElement.dataset.theme = theme.value;
});

/* --------------------------------------------------------------------------
 * The format each result is written in. Typed or pasted text is recognised by itself; these only decide how the app writes
 * a key it generates, a public key it deduces, a signature it makes, or what a field is converted to.
 * ------------------------------------------------------------------------ */

export type FormattedField = 'publicKey' | 'privateKey' | 'signature';
const FORMATTED_FIELDS: FormattedField[] = ['publicKey', 'privateKey', 'signature'];
const isFormat = (value: unknown): value is RawFormat => typeof value === 'string' && value in CODECS;

function loadFormats(): Record<FormattedField, RawFormat> {
    // earlier versions had a single choice, hex or base64, for everything
    const base: RawFormat = read('encoding') === 'hex' ? 'hex' : 'base64';
    const formats: Record<FormattedField, RawFormat> = { publicKey: base, privateKey: base, signature: base };
    try {
        const saved = JSON.parse(read('formats') ?? '{}');
        for (const field of FORMATTED_FIELDS) if (isFormat(saved?.[field])) formats[field] = saved[field];
    } catch {
        // unreadable value: keep the defaults
    }
    return formats;
}

const initial = loadFormats();
export const formatPreference = {
    publicKey: signal<RawFormat>(initial.publicKey),
    privateKey: signal<RawFormat>(initial.privateKey),
    signature: signal<RawFormat>(initial.signature),
};

effect(() => {
    write('formats', JSON.stringify(Object.fromEntries(FORMATTED_FIELDS.map((field) => [field, formatPreference[field].value]))));
});
