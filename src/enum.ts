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
    Base64 = 'base64',
}

/** Key files: a container that carries the key and says what it is (see keyfiles.ts). Only for the public and private key. */
export type EcosystemFormat = 'didkey' | 'stellar' | 'onion' | 'near' | 'solana';
export type KeyFileFormat = 'pem' | 'openssh' | 'jwk' | EcosystemFormat;

/** Everything the menu of a key can offer: a plain notation of the bytes, or a key file. */
export type FieldFormat = RawFormat | KeyFileFormat;
