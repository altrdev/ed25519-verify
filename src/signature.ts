import * as ed from 'noble-ed25519';
import { SignEncoding } from './enum';

const hexToBytes = (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const base64ToHex = (b64: string): string =>
    bytesToHex(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));

const hexToBase64 = (hex: string): string =>
    btoa(String.fromCharCode(...hexToBytes(hex)));

const utf8ToHex = (text: string): string => bytesToHex(new TextEncoder().encode(text));

const toHex = (value: string, encoding: SignEncoding): string =>
    encoding === SignEncoding.Base64 ? base64ToHex(value) : value;

// libsodium/NaCl style secret keys are 64 bytes (32-byte seed followed by the public key);
// noble only wants the seed.
const toSeedHex = (value: string, encoding: SignEncoding): string => {
    const hex = toHex(value, encoding);
    return hex.length === 128 ? hex.slice(0, 64) : hex;
};

class VerifyEd25519 {
    message: string;
    signature: string | null;
    publicKey: string | null;
    privateKey: string | null;

    constructor(message: string, signature: string | null, publicKey: string | null, privateKey: string | null) {
        this.message = message;
        this.signature = signature;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    async check(encoding: SignEncoding): Promise<boolean> {
        try {
            const signatureHex = toHex(this.signature ?? '', encoding);
            const publicKeyHex = toHex(this.publicKey ?? '', encoding);
            return await ed.verify(signatureHex, utf8ToHex(this.message), publicKeyHex);
        } catch (error) {
            console.log(error);
            return false;
        }
    }

    async sign(encoding: SignEncoding): Promise<string | null> {
        if (!this.privateKey) return this.fail('Private key missing');
        try {
            const privateKeyHex = toSeedHex(this.privateKey, encoding);
            const hexResult = await ed.sign(utf8ToHex(this.message), privateKeyHex);
            return encoding === SignEncoding.Base64 ? hexToBase64(hexResult) : hexResult;
        } catch (error) {
            return this.fail(error);
        }
    }

    async getPublicKey(encoding: SignEncoding): Promise<string | null> {
        if (!this.privateKey) return this.fail('Private key missing');
        try {
            const privateKeyHex = toSeedHex(this.privateKey, encoding);
            const hexResult = await ed.getPublicKey(privateKeyHex);
            return encoding === SignEncoding.Base64 ? hexToBase64(hexResult) : hexResult;
        } catch (error) {
            return this.fail(error);
        }
    }

    private fail(error: unknown): null {
        console.log(error);
        return null;
    }
}

export default VerifyEd25519;
