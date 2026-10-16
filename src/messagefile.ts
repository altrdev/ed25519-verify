/** A file chosen as the message: read in the browser only, the whole of it is held in memory. */

/** Larger files are refused: they would be read entirely into memory (and hashed twice by the signature). */
export const MAX_FILE_BYTES = 100 * 1024 * 1024;

export interface MessageFile {
    name: string;
    bytes: Uint8Array;
}

const megabytes = (bytes: number) => `${Math.round(bytes / (1024 * 1024))} MB`;

/** The content of the file, or the message to show when it is too large or cannot be read. */
export async function readMessageFile(file: File): Promise<MessageFile | string> {
    if (file.size > MAX_FILE_BYTES) {
        return `${file.name} is ${megabytes(file.size)}: the limit is ${megabytes(MAX_FILE_BYTES)}, the whole file is held in memory.`;
    }
    try {
        return { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
    } catch {
        return `${file.name} could not be read.`;
    }
}

/** "name · N bytes" */
export const describeFile = ({ name, bytes }: MessageFile): string => `${name} · ${bytes.length.toLocaleString('en-US')} bytes`;
