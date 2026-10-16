import { render, screen, fireEvent, waitFor } from '@testing-library/preact';
import { hexToBytes } from '../bytes';
import { encodePrivateKey, encodePublicKey } from '../keyfiles';
import { parseStructuredKey } from '../keyformats';
import { generateKeyPair } from '../signature';
import FormSign from '../FormSign';
import FormVerify from '../FormVerify';
import { formatButton, pickFormat, setFormats } from './helpers';
import { JWK_PRIVATE, JWK_PUBLIC, OPENSSH_PRIVATE, OPENSSH_PUBLIC, PKCS8_PEM, PUBLIC_HEX, SEED_HEX, SPKI_PEM } from './fixtures/keys';

const seed = hexToBytes(SEED_HEX);
const pub = hexToBytes(PUBLIC_HEX);
const same = (a: Uint8Array, b: Uint8Array) => expect(Array.from(a)).toEqual(Array.from(b));

describe('key file serializers', () => {
    it('write byte-exact what OpenSSL and ssh-keygen write', () => {
        expect(encodePrivateKey(seed, pub, 'pem')).toBe(PKCS8_PEM);
        expect(encodePublicKey(pub, 'pem')).toBe(SPKI_PEM);
        expect(encodePublicKey(pub, 'openssh')).toBe(OPENSSH_PUBLIC.replace(' test@example', ''));
        expect(JSON.parse(encodePrivateKey(seed, pub, 'jwk'))).toEqual(JSON.parse(JWK_PRIVATE));
        expect(JSON.parse(encodePublicKey(pub, 'jwk'))).toEqual(JSON.parse(JWK_PUBLIC));
    });

    it('read back as the same key', () => {
        for (const format of ['pem', 'openssh', 'jwk'] as const) {
            same(parseStructuredKey(encodePrivateKey(seed, pub, format)).privateKey!, seed);
            same(parseStructuredKey(encodePublicKey(pub, format)).publicKey!, pub);
        }
        same(parseStructuredKey(OPENSSH_PRIVATE).privateKey!, seed);
    });

    it('generate pairs in a key file format', async () => {
        const pair = await generateKeyPair('pem', 'openssh');
        expect(pair.privateKey).toContain('BEGIN PRIVATE KEY');
        expect(pair.publicKey).toMatch(/^ssh-ed25519 /);
    });
});

describe('key files in the forms', () => {
    beforeEach(() => setFormats('hex'));

    it('converts a public key to PEM, OpenSSH and JWK', () => {
        render(<FormVerify publicKey={PUBLIC_HEX} />);
        const field = () => (screen.getByLabelText('Public key') as HTMLTextAreaElement).value;
        pickFormat('Public key format', 'pem');
        expect(field()).toBe(SPKI_PEM);
        pickFormat('Public key format', 'openssh');
        expect(field()).toMatch(/^ssh-ed25519 /);
        pickFormat('Public key format', 'jwk');
        expect(JSON.parse(field())).toEqual(JSON.parse(JWK_PUBLIC));
        pickFormat('Public key format', 'hex');
        expect(field()).toBe(PUBLIC_HEX);
    });

    it('converts a private key to PEM, OpenSSH and JWK', async () => {
        render(<FormSign privateKey={SEED_HEX} />);
        const field = () => (screen.getByLabelText('Private key') as HTMLTextAreaElement).value;
        pickFormat('Private key format', 'pem');
        await waitFor(() => expect(field()).toBe(PKCS8_PEM));
        pickFormat('Private key format', 'jwk');
        await waitFor(() => expect(JSON.parse(field())).toEqual(JSON.parse(JWK_PRIVATE)));
        pickFormat('Private key format', 'openssh');
        await waitFor(() => expect(field()).toContain('BEGIN OPENSSH PRIVATE KEY'));
        pickFormat('Private key format', 'hex');
        await waitFor(() => expect(field()).toBe(SEED_HEX));
    });

    it('generates a key in the chosen key file format and shows the deduced public key', async () => {
        render(<FormSign />);
        pickFormat('Private key format', 'pem');
        fireEvent.click(screen.getByText('Generate'));
        await waitFor(() => expect((screen.getByLabelText('Private key') as HTMLTextAreaElement).value).toContain('BEGIN PRIVATE KEY'));
        pickFormat('Public key format', 'openssh');
        await waitFor(() => expect((screen.getByLabelText('Deduced Public key') as HTMLTextAreaElement).value).toMatch(/^ssh-ed25519 /));
        expect(formatButton('Private key format')).toHaveTextContent('PEM');
    });
});
