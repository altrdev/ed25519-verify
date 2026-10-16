import { signal, effect } from '@preact/signals';
import { SignEncoding } from './enum';

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
/** How results (signature, generated and deduced keys) are written. Inputs are detected, not selected. */
export const outputEncoding = signal<SignEncoding>(
    read('encoding') === SignEncoding.Hex ? SignEncoding.Hex : SignEncoding.Base64
);

effect(() => {
    write('theme', theme.value);
    document.documentElement.dataset.theme = theme.value;
});

effect(() => {
    write('encoding', outputEncoding.value);
});
