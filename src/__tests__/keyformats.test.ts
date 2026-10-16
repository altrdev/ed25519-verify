import { bytesToHex, parseBase64 } from '../bytes';
import { detectKeyFormat, isStructuredKey, KeyFormatError, parseStructuredKey } from '../keyformats';
import VerifyEd25519, { InputError } from '../signature';
import { MessageFormat, SignEncoding } from '../enum';
import * as K from './fixtures/keys';

const hex = (bytes?: Uint8Array) => (bytes ? bytesToHex(bytes) : undefined);

// signature of "000000001" with the key of the fixtures (the same one the signature tests use)
const SIGNATURE_HEX = 'f5ab3aa888c6b0ab792fe9b9bdc26132b374d3ba18300424e3252d6417954372d15d66bdf51da24adad7343f545aa9127827e2281e7968ef9a5188cc23a5ef09';

const messageOf = (run: () => unknown): string => {
    try {
        run();
    } catch (error) {
        expect(error).toBeInstanceOf(KeyFormatError);
        return (error as Error).message;
    }
    throw new Error('expected the key to be rejected');
};

describe('Key format detection', () => {
    it('names the format of a pasted key', () => {
        expect(detectKeyFormat(K.PKCS8_PEM)).toBe('PEM (PKCS#8)');
        expect(detectKeyFormat(K.SPKI_PEM)).toBe('PEM (SPKI)');
        expect(detectKeyFormat(K.OPENSSH_PRIVATE)).toBe('OpenSSH private key');
        expect(detectKeyFormat(K.OPENSSH_PUBLIC)).toBe('OpenSSH public key');
        expect(detectKeyFormat(K.JWK_PUBLIC)).toBe('JWK');
        expect(detectKeyFormat(`\n  ${K.JWK_PUBLIC}  \n`)).toBe('JWK');
        expect(detectKeyFormat('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----')).toBe('PEM');
    });

    it('leaves plain hex and base64 alone', () => {
        for (const plain of [K.PUBLIC_HEX, 'X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0=', '', '   ', 'ssh-ed25519']) {
            expect(detectKeyFormat(plain)).toBeNull();
            expect(isStructuredKey(plain)).toBe(false);
        }
    });
});

describe('Key format parsing', () => {
    it('reads a PKCS#8 private key (PEM)', () => {
        const key = parseStructuredKey(K.PKCS8_PEM);
        expect(key.format).toBe('PEM (PKCS#8)');
        expect(hex(key.privateKey)).toBe(K.SEED_HEX);
        expect(key.publicKey).toBeUndefined();
    });

    it('reads a SubjectPublicKeyInfo public key (PEM)', () => {
        const key = parseStructuredKey(K.SPKI_PEM);
        expect(key.format).toBe('PEM (SPKI)');
        expect(hex(key.publicKey)).toBe(K.PUBLIC_HEX);
        expect(key.privateKey).toBeUndefined();
    });

    it('reads the example of RFC 8410', () => {
        const key = parseStructuredKey(K.RFC8410.pem);
        expect(hex(key.privateKey)).toBe(K.RFC8410.seedHex);
    });

    it('reads an OpenSSH public key, with or without comment', () => {
        expect(hex(parseStructuredKey(K.OPENSSH_PUBLIC).publicKey)).toBe(K.PUBLIC_HEX);
        const withoutComment = K.OPENSSH_PUBLIC.split(' ').slice(0, 2).join(' ');
        expect(hex(parseStructuredKey(withoutComment).publicKey)).toBe(K.PUBLIC_HEX);
    });

    it('reads an unencrypted OpenSSH private key, public part included', () => {
        const key = parseStructuredKey(K.OPENSSH_PRIVATE);
        expect(key.format).toBe('OpenSSH private key');
        expect(hex(key.privateKey)).toBe(K.SEED_HEX);
        expect(hex(key.publicKey)).toBe(K.PUBLIC_HEX);
    });

    it('reads private and public JWKs', () => {
        const priv = parseStructuredKey(K.JWK_PRIVATE);
        expect(hex(priv.privateKey)).toBe(K.SEED_HEX);
        expect(hex(priv.publicKey)).toBe(K.PUBLIC_HEX);
        const pub = parseStructuredKey(K.JWK_PUBLIC);
        expect(hex(pub.publicKey)).toBe(K.PUBLIC_HEX);
        expect(pub.privateKey).toBeUndefined();
        expect(hex(parseStructuredKey(JSON.stringify(JSON.parse(K.JWK_PRIVATE), null, 2)).privateKey)).toBe(K.SEED_HEX);
    });

    it('tolerates what a copy and paste does to a PEM', () => {
        const crlf = K.PKCS8_PEM.replace(/\n/g, '\r\n');
        const indented = K.PKCS8_PEM.split('\n').map((line) => `    ${line}`).join('\n');
        const noFinalNewline = K.PKCS8_PEM.trimEnd();
        const concatenated = K.PKCS8_PEM + K.SPKI_PEM; // `cat private.pem public.pem`
        for (const variant of [crlf, indented, noFinalNewline, `\n\n${K.PKCS8_PEM}\n\n`, concatenated]) {
            expect(hex(parseStructuredKey(variant).privateKey)).toBe(K.SEED_HEX);
        }
    });
});

describe('Key format errors', () => {
    it('says which other type of key it is', () => {
        expect(messageOf(() => parseStructuredKey(K.WRONG.x25519Pem))).toBe('this is an X25519 key, only Ed25519 is supported.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.ed448Pem))).toBe('this is an Ed448 key, only Ed25519 is supported.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.ecPem))).toBe('this is an EC key, only Ed25519 is supported.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.rsaPem))).toBe('this is an RSA key, only Ed25519 is supported.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.rsaPublicPem))).toBe('this is an RSA key, only Ed25519 is supported.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.opensshRsaPublic))).toBe('this is a "ssh-rsa" key, only ssh-ed25519 is supported.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.opensshEcdsaPublic))).toBe('this is a "ecdsa-sha2-nistp256" key, only ssh-ed25519 is supported.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.opensshRsaPrivate))).toBe('this is a "ssh-rsa" key, only ssh-ed25519 is supported.');
        expect(messageOf(() => parseStructuredKey('sk-ssh-ed25519@openssh.com AAAA'))).toContain('security-key');
    });

    it('refuses encrypted keys and says how to decrypt them', () => {
        expect(messageOf(() => parseStructuredKey(K.WRONG.encryptedPkcs8Pem))).toContain('encrypted with a passphrase');
        expect(messageOf(() => parseStructuredKey(K.WRONG.encryptedPkcs8Pem))).toContain('openssl pkey');
        expect(messageOf(() => parseStructuredKey(K.WRONG.opensshEncrypted))).toContain('ssh-keygen -p');
        const legacy = '-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END PRIVATE KEY-----';
        expect(messageOf(() => parseStructuredKey(legacy))).toContain('encrypted with a passphrase');
    });

    it('explains JWKs that are not usable', () => {
        expect(messageOf(() => parseStructuredKey(K.WRONG.jwkRsa))).toBe('this is a "RSA" JWK, not an Ed25519 key.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.jwkX25519))).toBe('the JWK curve is "X25519", not Ed25519.');
        expect(messageOf(() => parseStructuredKey(K.WRONG.jwkSet))).toContain('JWK Set');
        expect(messageOf(() => parseStructuredKey('{"kty": "OKP",'))).toBe('the JWK is not valid JSON.');
        expect(messageOf(() => parseStructuredKey('{}'))).toContain('no "kty"');
        expect(messageOf(() => parseStructuredKey('{"kty":"OKP","crv":"Ed25519"}'))).toContain('neither "x"');
        expect(messageOf(() => parseStructuredKey('{"kty":"OKP","crv":"Ed25519","x":"AAAA"}'))).toBe('the JWK member "x" must be 32 bytes in base64url.');
        expect(messageOf(() => parseStructuredKey('{"kty":"OKP","crv":"Ed25519","x":42}'))).toContain('"x"');
        expect(messageOf(() => parseStructuredKey('{"kty":"OKP"}'))).toContain('curve');
    });

    it('explains broken PEM blocks', () => {
        expect(messageOf(() => parseStructuredKey('-----BEGIN PRIVATE KEY-----\nAAAA'))).toContain('incomplete');
        expect(messageOf(() => parseStructuredKey('-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----'))).toContain('not valid base64');
        expect(messageOf(() => parseStructuredKey('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----'))).toContain('malformed');
        expect(messageOf(() => parseStructuredKey('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'))).toContain('certificate');
        expect(messageOf(() => parseStructuredKey('-----BEGIN SOMETHING-----\nAAAA\n-----END SOMETHING-----'))).toContain('"SOMETHING"');
        expect(messageOf(() => parseStructuredKey('ssh-ed25519 !!!'))).toContain('not valid base64');
    });

    it('never fails with anything but a KeyFormatError, whatever the data', () => {
        const der = (pem: string) => parseBase64(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''))!;
        const asPem = (label: string, bytes: Uint8Array) =>
            `-----BEGIN ${label}-----\n${btoa(String.fromCharCode(...bytes))}\n-----END ${label}-----`;
        const samples: [string, Uint8Array][] = [
            ['PRIVATE KEY', der(K.PKCS8_PEM)],
            ['PUBLIC KEY', der(K.SPKI_PEM)],
            ['OPENSSH PRIVATE KEY', der(K.OPENSSH_PRIVATE)],
        ];
        let attempts = 0;
        for (const [label, bytes] of samples) {
            for (let length = 0; length < bytes.length; length++) {   // every truncation
                try { parseStructuredKey(asPem(label, bytes.slice(0, length))); } catch (e) { expect(e).toBeInstanceOf(KeyFormatError); }
                attempts++;
            }
            for (let index = 0; index < bytes.length; index++) {      // every single byte corrupted
                const corrupted = bytes.slice();
                corrupted[index] ^= 0xff;
                try { parseStructuredKey(asPem(label, corrupted)); } catch (e) { expect(e).toBeInstanceOf(KeyFormatError); }
                attempts++;
            }
        }
        expect(attempts).toBeGreaterThan(300);
    });
});

describe('Pasted keys used by the signature code', () => {
    const ENCODINGS = [SignEncoding.Hex, SignEncoding.Base64];
    const toEncoding = (hexValue: string, encoding: SignEncoding) =>
        encoding === SignEncoding.Hex ? hexValue : btoa(String.fromCharCode(...(hexValue.match(/../g) ?? []).map((h) => parseInt(h, 16))));

    it.each(ENCODINGS)('signs with a private key in any format, the same way (%s selected)', async (encoding) => {
        const expected = toEncoding(SIGNATURE_HEX, encoding);
        for (const privateKey of [K.PKCS8_PEM, K.OPENSSH_PRIVATE, K.JWK_PRIVATE]) {
            const signer = new VerifyEd25519('000000001', null, null, privateKey);
            expect(await signer.sign(encoding)).toBe(expected);
            expect(await signer.getPublicKey(encoding)).toBe(toEncoding(K.PUBLIC_HEX, encoding));
        }
    });

    it.each(ENCODINGS)('verifies with a public key in any format (%s selected)', async (encoding) => {
        const signature = toEncoding(SIGNATURE_HEX, encoding);
        for (const publicKey of [K.SPKI_PEM, K.OPENSSH_PUBLIC, K.JWK_PUBLIC, K.JWK_PRIVATE, K.OPENSSH_PRIVATE]) {
            const verifier = new VerifyEd25519('000000001', signature, publicKey, null, MessageFormat.Text);
            expect(await verifier.verdict(encoding)).toBe('valid');
        }
        const wrong = new VerifyEd25519('000000002', signature, K.SPKI_PEM, null);
        expect(await wrong.verdict(encoding)).toBe('invalid');
    });

    it('reports a rejected key on the field it was pasted in', () => {
        const errors = new VerifyEd25519('', null, K.WRONG.rsaPublicPem, K.WRONG.encryptedPkcs8Pem)
            .validate(SignEncoding.Base64, ['publicKey', 'privateKey']);
        expect(errors.publicKey).toBe('Public key: this is an RSA key, only Ed25519 is supported.');
        expect(errors.privateKey).toMatch(/^Private key: the key is encrypted with a passphrase/);
    });

    it('tells a public key from a private key pasted in the wrong field', () => {
        const wrongWayRound = new VerifyEd25519('', null, K.PKCS8_PEM, K.SPKI_PEM)
            .validate(SignEncoding.Hex, ['publicKey', 'privateKey']);
        expect(wrongWayRound.privateKey).toBe('Private key: this is a public key (PEM (SPKI)), the private key goes here.');
        expect(wrongWayRound.publicKey).toContain('this is a private key (PEM (PKCS#8)) that does not include its public part');
    });

    it('still reports plain hex and base64 problems the old way', () => {
        const errors = new VerifyEd25519('', 'zz', 'abc', null).validate(SignEncoding.Hex, ['publicKey', 'signature']);
        expect(errors.publicKey).toBe('Public key is not valid hex.');
        expect(errors.signature).toBe('Signature is not valid hex.');
        // a signature is never read as PEM / JWK
        expect(new VerifyEd25519('', '{"kty":"OKP"}', null, null).validate(SignEncoding.Hex, ['signature']).signature)
            .toBe('Signature is not valid hex.');
    });

    it('rejects with an InputError on the right field when a rejected key is used', async () => {
        await expect(new VerifyEd25519('x', null, null, K.WRONG.rsaPem).sign(SignEncoding.Hex))
            .rejects.toMatchObject({ field: 'privateKey' });
        await expect(new VerifyEd25519('x', SIGNATURE_HEX, K.WRONG.jwkRsa, null).verdict(SignEncoding.Hex))
            .rejects.toBeInstanceOf(InputError);
    });
});
