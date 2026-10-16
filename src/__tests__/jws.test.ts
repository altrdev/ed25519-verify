import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { bytesToHex } from '../bytes';
import {
    bytesOfInput,
    checkHeaderToSign,
    decodeBase64Url,
    describePayload,
    encodeBase64Url,
    JwsError,
    parseJws,
    signingInputOf,
    timeNotes,
    tokenOf,
} from '../jws';
import { verdictOf } from '../signature';

// RFC 8037, appendix A.4: the key of A.1 (it is the key of RFC 8032 test 1) signing "Example of Ed25519 signing"
const D = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';
const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const RFC_TOKEN =
    'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';

const publicKey = decodeBase64Url(X) as Uint8Array;
const seed = decodeBase64Url(D) as Uint8Array;
const sign = (signingInput: string) => ed.signAsync(bytesOfInput(signingInput), seed);
const message = (build: () => unknown) => {
    try {
        build();
    } catch (error) {
        return error instanceof JwsError ? error.message : `other: ${error}`;
    }
    return 'no error';
};

describe('base64url', () => {
    it('is strict: no padding, no + or /, no impossible length', () => {
        expect(decodeBase64Url('')).toEqual(new Uint8Array(0));
        expect(bytesToHex(decodeBase64Url('-_8') as Uint8Array)).toBe('fbff');
        expect(decodeBase64Url('ab=')).toBeNull();
        expect(decodeBase64Url('a+b/')).toBeNull();
        expect(decodeBase64Url('abcde')).toBeNull(); // 5 characters cannot be bytes
        expect(decodeBase64Url('ab cd')).toBeNull();
    });

    it('round trips every length', () => {
        for (let length = 0; length < 70; length++) {
            const bytes = crypto.getRandomValues(new Uint8Array(length));
            expect(Array.from(decodeBase64Url(encodeBase64Url(bytes)) as Uint8Array)).toEqual(Array.from(bytes));
            expect(encodeBase64Url(bytes)).not.toMatch(/[=+/]/);
        }
    });
});

describe('the example of RFC 8037', () => {
    it('is parsed and verifies', async () => {
        const parsed = parseJws(RFC_TOKEN);
        expect(parsed.header).toEqual({ alg: 'EdDSA' });
        expect(new TextDecoder().decode(parsed.payload)).toBe('Example of Ed25519 signing');
        expect(await verdictOf(parsed.signature, parsed.signingInput, publicKey)).toBe('valid');
    });

    it('is produced byte for byte by signing the same input (Ed25519 is deterministic)', async () => {
        const input = signingInputOf('{"alg":"EdDSA"}', 'Example of Ed25519 signing');
        expect(tokenOf(input, await sign(input))).toBe(RFC_TOKEN);
    });

    it('stops verifying when any character of the payload or the signature changes', async () => {
        const [header, payload, signature] = RFC_TOKEN.split('.');
        for (const changed of [`${header}.${payload.slice(0, -1)}A.${signature}`, `${header}.${payload}.${signature.slice(0, -2)}AA`]) {
            const parsed = parseJws(changed);
            expect(await verdictOf(parsed.signature, parsed.signingInput, publicKey)).toBe('invalid');
        }
    });

    it('tolerates the "Bearer " of an Authorization header and surrounding spaces', () => {
        expect(parseJws(`  Bearer ${RFC_TOKEN}\n`).signature).toHaveLength(64);
    });
});

describe('what is refused, and why', () => {
    const forged = (header: object, payload = 'x', signature = new Uint8Array(64)) =>
        `${encodeBase64Url(new TextEncoder().encode(JSON.stringify(header)))}.${encodeBase64Url(new TextEncoder().encode(payload))}.${encodeBase64Url(signature)}`;

    it('an unsigned token ("none") and other algorithms', () => {
        expect(message(() => parseJws(forged({ alg: 'none' })))).toMatch(/"none".*not signed at all/);
        expect(message(() => parseJws(forged({ alg: 'HS256' })))).toMatch(/"HS256".*EdDSA \(Ed25519\) tokens only/);
        expect(message(() => parseJws(forged({ alg: 'RS256' })))).toMatch(/"RS256"/);
        expect(message(() => parseJws(forged({ typ: 'JWT' })))).toMatch(/no "alg"/);
        expect(message(() => parseJws(forged({ alg: 'eddsa' })))).toMatch(/"eddsa"/); // the name is case sensitive
    });

    it('a header that needs an extension ("crit")', () => {
        expect(message(() => parseJws(forged({ alg: 'EdDSA', crit: ['exp'] })))).toMatch(/crit/);
    });

    it('the wrong number of parts, padding, other alphabets, a signature of another size', () => {
        expect(message(() => parseJws(''))).toMatch(/Paste a token/);
        expect(message(() => parseJws('a.b'))).toMatch(/three parts.*has 2/);
        expect(message(() => parseJws('a.b.c.d'))).toMatch(/has 4/);
        expect(message(() => parseJws('a.b.c.d.e'))).toMatch(/encrypted token/);
        expect(message(() => parseJws(`${RFC_TOKEN}=`))).toMatch(/signature has "=" padding/);
        expect(message(() => parseJws(RFC_TOKEN.replace('-', '+')))).toMatch(/not base64url/);
        expect(message(() => parseJws(forged({ alg: 'EdDSA' }, 'x', new Uint8Array(63))))).toMatch(/63 bytes/);
    });

    it('a header that is not JSON, not an object or not text', () => {
        const part = (text: string) => encodeBase64Url(new TextEncoder().encode(text));
        const token = (header: string) => `${part(header)}.${part('x')}.${encodeBase64Url(new Uint8Array(64))}`;
        expect(message(() => parseJws(token('not json')))).toMatch(/not JSON/);
        expect(message(() => parseJws(token('[1]')))).toMatch(/JSON object/);
        expect(
            message(() => parseJws(`${encodeBase64Url(new Uint8Array([0xff, 0xfe]))}.eA.${encodeBase64Url(new Uint8Array(64))}`)),
        ).toMatch(/not valid UTF-8/);
    });
});

describe('the payload of a token', () => {
    it('is shown as JSON, text or nothing, with the times of a JWT', () => {
        const encoder = new TextEncoder();
        const info = describePayload(encoder.encode('{"sub":"a","exp":1700000000,"iat":1600000000,"nbf":1650000000,"x":"1"}'));
        expect(JSON.parse(info.json as string)).toMatchObject({ sub: 'a' });
        expect(info).toMatchObject({ exp: 1700000000, iat: 1600000000, nbf: 1650000000 });
        expect(describePayload(encoder.encode('just text'))).toEqual({ text: 'just text', json: null });
        expect(describePayload(encoder.encode('[1,2]')).json).toBeNull();
        expect(describePayload(new Uint8Array([0xff]))).toEqual({ text: null, json: null });
        expect(describePayload(encoder.encode('{"exp":"soon"}')).exp).toBeUndefined();
    });

    it('is compared with the clock without changing anything else', () => {
        const info = { text: '', json: null, exp: 1000, nbf: 500, iat: 400 };
        expect(timeNotes(info, 2000)).toEqual([
            'Expired: it expired on 1970-01-01T00:16:40Z.',
            'Valid since 1970-01-01T00:08:20Z.',
            'Issued on 1970-01-01T00:06:40Z.',
        ]);
        expect(timeNotes({ ...info, nbf: 3000 }, 2000)[1]).toBe('Not valid yet: it starts on 1970-01-01T00:50:00Z.');
        expect(timeNotes({ ...info, exp: 5000 }, 2000)[0]).toMatch(/^Expires on/);
    });
});

describe('creating a token', () => {
    it('accepts only an EdDSA header', () => {
        expect(message(() => checkHeaderToSign('{"alg":"EdDSA","typ":"JWT"}'))).toBe('no error');
        expect(message(() => checkHeaderToSign('{"alg":"HS256"}'))).toMatch(/EdDSA/);
        expect(message(() => checkHeaderToSign('{'))).toMatch(/not JSON/);
        expect(message(() => checkHeaderToSign('[]'))).toMatch(/object/);
        expect(message(() => checkHeaderToSign('{"alg":"EdDSA","crit":[]}'))).toMatch(/crit/);
    });

    it('signs the texts exactly as typed, spaces and accents included', async () => {
        const headerText = '{ "alg" : "EdDSA",\n "kid": "chiave-è" }';
        const payloadText = '{"nome":"José","emoji":"🔑"}';
        const input = signingInputOf(headerText, payloadText);
        const token = tokenOf(input, await sign(input));
        const parsed = parseJws(token);
        expect(parsed.headerText).toBe(headerText);
        expect(new TextDecoder().decode(parsed.payload)).toBe(payloadText);
        expect(await verdictOf(parsed.signature, parsed.signingInput, publicKey)).toBe('valid');
    });
});

describe("against Node's crypto, which knows nothing about this code", () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', d: D, x: X };
    const nodePrivate = createPrivateKey({ key: jwk, format: 'jwk' });
    const nodePublic = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: X }, format: 'jwk' });

    it('verifies a token that Node signed', async () => {
        for (const payload of ['', 'hello', '{"sub":"1234567890","name":"Zoë","iat":1516239022}', 'x'.repeat(3000)]) {
            const input = signingInputOf('{"alg":"EdDSA","typ":"JWT"}', payload);
            const signature = new Uint8Array(nodeSign(null, Buffer.from(input), nodePrivate));
            const parsed = parseJws(tokenOf(input, signature));
            expect(await verdictOf(parsed.signature, parsed.signingInput, publicKey)).toBe('valid');
        }
    });

    it('makes a token that Node verifies', async () => {
        for (const payload of ['', 'hello', '{"sub":"1234567890"}', 'ünï©ode 🔑']) {
            const input = signingInputOf('{"alg":"EdDSA"}', payload);
            const token = tokenOf(input, await sign(input));
            const [header, body, signature] = token.split('.');
            expect(nodeVerify(null, Buffer.from(`${header}.${body}`), nodePublic, Buffer.from(signature, 'base64url'))).toBe(true);
        }
    });
});
