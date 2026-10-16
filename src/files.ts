/**
 * Keys and signatures as files: reading one into a field (picked or dropped) and saving one from a field. Everything happens in the
 * browser: `FileReader` for reading, a `Blob` and a link with `download` for saving; nothing is sent anywhere.
 */
import { bytesToHex } from './bytes';
import type { FieldFormat } from './enum';

export type FileKind = 'key' | 'signature' | 'text';

/** A key file is a few hundred bytes (an encrypted OpenSSH one a little more): anything bigger is not a key. */
export const MAX_FILE_BYTES = 16 * 1024;

/** The sizes of a raw binary file (no text): a seed or a seed followed by the public key; a signature. */
const RAW_SIZES: Record<FileKind, number[]> = { key: [32, 64], signature: [64], text: [] };

export class FileError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'FileError';
    }
}

const readBytes = (file: Blob): Promise<Uint8Array> =>
    new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
        reader.onerror = () => reject(new FileError('The file could not be read.'));
        reader.readAsArrayBuffer(file);
    });

/** Text without control characters other than spaces and line breaks (a BOM is dropped), or null when the bytes are not text. */
function asText(bytes: Uint8Array): string | null {
    let text: string;
    try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
        return null;
    }
    // biome-ignore lint/suspicious/noControlCharactersInRegex: this is exactly what is being looked for
    return /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text) ? null : text.replace(/^﻿/, '');
}

/**
 * The text to put in a field for a file: its content when it is text (PEM, OpenSSH, JWK, hex, base64...), or, for a raw binary
 * file of the size of a key or of a signature, its bytes written as hex.
 */
export async function readFileForField(file: File, kind: FileKind): Promise<string> {
    if (file.size > MAX_FILE_BYTES) {
        throw new FileError(
            `${file.name || 'The file'} is too big for a key or a signature (${file.size} bytes, at most ${MAX_FILE_BYTES}).`,
        );
    }
    const bytes = await readBytes(file);
    const text = asText(bytes);
    if (text !== null) return text;
    if (RAW_SIZES[kind].includes(bytes.length)) return bytesToHex(bytes);
    if (kind === 'text') throw new FileError(`${file.name || 'The file'} is not a text file.`);
    throw new FileError(
        `${file.name || 'The file'} is not text, and it is not ${RAW_SIZES[kind].join(' or ')} bytes of a raw ${kind === 'key' ? 'key' : 'signature'}.`,
    );
}

/** The name a file is saved with: the one the other tools expect for the format (id_ed25519, public.pem...). */
export function fileNameFor(kind: 'public' | 'private' | 'signature', format: FieldFormat | null): string {
    if (kind === 'signature') return 'signature.sig';
    if (kind === 'private') {
        if (format === 'openssh') return 'id_ed25519';
        if (format === 'pem') return 'private.pem';
        if (format === 'jwk') return 'private.jwk';
        if (format === 'solana') return 'keypair.json';
        return 'private-key.txt';
    }
    if (format === 'openssh') return 'id_ed25519.pub';
    if (format === 'pem') return 'public.pem';
    if (format === 'jwk') return 'public.jwk';
    return 'public-key.txt';
}

/** Saves a text through the browser's downloads. The file always ends with a line break. */
export function downloadText(filename: string, text: string): void {
    const blob = new Blob([text.endsWith('\n') ? text : `${text}\n`], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    // (octet-stream: with text/plain a browser adds .txt to a name without extension, such as id_ed25519)
    // the download has started when click() returns; the address can be released right after
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
