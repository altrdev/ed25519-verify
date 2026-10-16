/** Hex and base64 helpers shared by the signature code and the key format parsers. */

export const bytesToHex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export const hexToBytes = (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
};

export const bytesToBase64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));

/** Strict hex: digits only, even length. Returns null when the text is not hex. */
export function parseHex(value: string): Uint8Array | null {
    return /^[0-9a-f]+$/i.test(value) && value.length % 2 === 0 ? hexToBytes(value) : null;
}

/** Base64, standard or URL-safe alphabet, padding optional. Returns null when the text is not base64. */
export function parseBase64(value: string): Uint8Array | null {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) return null;
    const body = normalized.replace(/=+$/, '');
    if (body.length % 4 === 1) return null;
    try {
        return Uint8Array.from(atob(body.padEnd(Math.ceil(body.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
    } catch {
        return null;
    }
}
