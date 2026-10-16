/** How a key, a signature or a result is written as text. See codecs.ts for the full list. */
export type RawFormat = 'hex' | 'hex0x' | 'base64' | 'base64url' | 'base58' | 'base32' | 'bytes';

/**
 * The two formats the output selector offers today: a subset of RawFormat. Kept as a const object (not an enum) so that
 * `SignEncoding.Hex` is simply the string 'hex' and can be used wherever a RawFormat is expected.
 */
export const SignEncoding = { Hex: 'hex', Base64: 'base64' } as const;
export type SignEncoding = (typeof SignEncoding)[keyof typeof SignEncoding];

/** How the message field is interpreted: plain text, or bytes written in hex / base64. */
export enum MessageFormat {
    Text = 'text',
    Hex = 'hex',
    Base64 = 'base64'
}
