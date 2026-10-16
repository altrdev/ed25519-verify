import { render, screen, fireEvent, within } from '@testing-library/preact';
import { formatButton, pickFormat, setFormats } from './helpers';
import FormVerify from '../FormVerify';
import { hexToBytes } from '../bytes';
import { encodeAs } from '../codecs';

const messageFormat = (name: string) => within(screen.getByRole('group', { name: 'Message format' })).getByRole('button', { name });

const signature = 'BhqKbhnVH3kaNARj/Vht7ImJJ2LMM5TOla7k5OTITjdZ+GpWTY69wH79vRowPmq0c2KFDNipPsUcXSAwrviqDA==';
const publicKey = 'u6xMxXSXi/dL9tWPS+qfxiOHMA6c2Czwh/k2hy/wx/U=';

describe('FormVerify component', () => {
    beforeEach(() => {
        setFormats('base64');
    });

    it('should render', () => {
        render(<FormVerify />);
        expect(screen.getByLabelText('Public key')).toBeInTheDocument();
    });

    it('should explain what is missing instead of calling the signature wrong', async () => {
        render(<FormVerify />);
        fireEvent.click(screen.getByText('Verify'));
        expect(await screen.findByText('Public key is required.')).toBeInTheDocument();
        expect(screen.getByText('Signature is required.')).toBeInTheDocument();
        expect(screen.getByLabelText('Public key')).toHaveAttribute('aria-invalid', 'true');
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
    });

    it('should report a malformed field and clear the message when it is edited', async () => {
        render(<FormVerify publicKey="shor" signature={signature} message="000000102" />);
        fireEvent.click(screen.getByText('Verify'));
        expect(await screen.findByText('Public key: expected 32 bytes, got 3 as base64 or 3 as base58.')).toBeInTheDocument();
        expect(screen.getByLabelText('Signature')).not.toHaveAttribute('aria-invalid'); // only the faulty field is flagged

        fireEvent.input(screen.getByLabelText('Public key'), { target: { value: publicKey } });
        expect(screen.queryByText(/Public key: expected/)).not.toBeInTheDocument();
        expect(screen.getByLabelText('Public key')).not.toHaveAttribute('aria-invalid');
    });

    it('should render with error banner when the signature does not match', async () => {
        render(<FormVerify publicKey={publicKey} signature={signature} message="hello world!" />);
        fireEvent.click(screen.getByText('Verify'));
        const alert = await screen.findByRole('alert');
        expect(alert.textContent?.trim()).toBe('Signature is wrong');
    });

    it('should render with valid banner', async () => {
        render(<FormVerify message="000000102" signature={signature} publicKey={publicKey} />);
        fireEvent.click(screen.getByText('Verify'));
        const alert = await screen.findByRole('alert');
        expect(alert.textContent?.trim()).toBe('Signature is valid');
    });

    it('should hide the result when an input changes', async () => {
        render(<FormVerify publicKey={publicKey} signature={signature} message="hello world!" />);
        fireEvent.click(screen.getByText('Verify'));
        await screen.findByRole('alert');
        fireEvent.input(screen.getByLabelText('Message'), { target: { value: 'changed' } });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('verifies a message given as hex or base64', async () => {
        // "000000102" as UTF-8 bytes
        for (const [format, value] of [
            ['Hex', '303030303030313032'],
            ['Base64', 'MDAwMDAwMTAy'],
        ]) {
            const { unmount } = render(<FormVerify publicKey={publicKey} signature={signature} />);
            fireEvent.click(messageFormat(format));
            fireEvent.input(screen.getByLabelText('Message'), { target: { value } });
            fireEvent.click(screen.getByText('Verify'));
            expect((await screen.findByRole('alert')).textContent?.trim()).toBe('Signature is valid');
            unmount();
        }
    });

    it('flags a message that is not valid in the selected format instead of calling the signature wrong', async () => {
        render(<FormVerify publicKey={publicKey} signature={signature} message="zz" />);
        fireEvent.click(messageFormat('Hex'));
        fireEvent.click(screen.getByText('Verify'));
        expect(await screen.findByText('Message is not valid hex.')).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
    });

    it('hides the previous result when the message format changes', async () => {
        render(<FormVerify publicKey={publicKey} signature={signature} message="000000102" />);
        fireEvent.click(screen.getByText('Verify'));
        await screen.findByRole('alert');
        fireEvent.click(messageFormat('Hex'));
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('says so when a signature is only accepted under the permissive ZIP215 rules', async () => {
        setFormats('hex');
        const identity = '01' + '00'.repeat(31);
        render(<FormVerify publicKey={identity} signature={identity + '00'.repeat(32)} message="anything" />);
        fireEvent.click(screen.getByText('Verify'));
        const alert = await screen.findByRole('alert');
        expect(alert.textContent).toContain('not valid under the strict RFC 8032 rules');
        expect(alert.textContent).toContain('ZIP215');
        expect(alert).toHaveClass('warning');
        expect(screen.queryByText('Signature is valid')).not.toBeInTheDocument();
    });
});

describe('FormVerify with keys in other formats', () => {
    // the key of the key format fixtures, and its signature of "000000001"
    const SPKI_PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAX4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0=\n-----END PUBLIC KEY-----\n';
    const SIGNATURE_HEX =
        'f5ab3aa888c6b0ab792fe9b9bdc26132b374d3ba18300424e3252d6417954372d15d66bdf51da24adad7343f545aa9127827e2281e7968ef9a5188cc23a5ef09';

    beforeEach(() => {
        setFormats('hex');
    });

    it('verifies with a PEM public key and shows the detected format', async () => {
        render(<FormVerify publicKey={SPKI_PEM} signature={SIGNATURE_HEX} message="000000001" />);
        expect(screen.getByText('Detected format: PEM (SPKI)')).toBeInTheDocument();
        fireEvent.click(screen.getByText('Verify'));
        expect((await screen.findByRole('alert')).textContent?.trim()).toBe('Signature is valid');
    });

    it('verifies with an OpenSSH or JWK public key, whatever the selected encoding', async () => {
        const jwk = '{"kty":"OKP","crv":"Ed25519","x":"X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0"}';
        for (const key of [jwk, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF+C1Upo0jl56XVoZra5DOJ37zTh1drsOHHFQJ1WNRqN me@host']) {
            const { unmount } = render(<FormVerify publicKey={key} signature={SIGNATURE_HEX} message="000000001" />);
            fireEvent.click(screen.getByText('Verify'));
            expect((await screen.findByRole('alert')).textContent?.trim()).toBe('Signature is valid');
            unmount();
        }
    });

    it('explains a key of another type instead of calling the signature wrong', async () => {
        const rsa = '-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----';
        render(<FormVerify publicKey={rsa} signature={SIGNATURE_HEX} message="000000001" />);
        fireEvent.click(screen.getByText('Verify'));
        expect(await screen.findByText('Public key: this is an RSA key, only Ed25519 is supported.')).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
        // the "Detected" note gives way to the error
        expect(screen.queryByText(/^Detected format/)).not.toBeInTheDocument();
    });

    it('shows a multi-line key in full instead of its last two lines', () => {
        const { unmount } = render(<FormVerify publicKey={SPKI_PEM} />);
        // BEGIN line, key line, END line: three rows instead of the default two
        expect(screen.getByLabelText('Public key')).toHaveAttribute('rows', '3');
        unmount();
        render(<FormVerify publicKey={'x\n'.repeat(30)} />);
        expect(screen.getByLabelText('Public key')).toHaveAttribute('rows', '8'); // capped
    });

    it('has no encoding to choose: keys and signature are recognised, even when written differently', async () => {
        render(<FormVerify />);
        expect(screen.queryByText(/encoding/i)).not.toBeInTheDocument();
        // hex public key, base64 signature
        const hexPublicKey = '5f82d54a68d23979e9756866b6b90ce277ef34e1d5daec3871c5409d56351a8d';
        const base64Signature = '9as6qIjGsKt5L+m5vcJhMrN007oYMAQk4yUtZBeVQ3LRXWa99R2iStrXND9UWqkSeCfiKB55aO+aUYjMI6XvCQ==';
        fireEvent.input(screen.getByLabelText('Public key'), { target: { value: hexPublicKey } });
        fireEvent.input(screen.getByLabelText('Message'), { target: { value: '000000001' } });
        fireEvent.input(screen.getByLabelText('Signature'), { target: { value: base64Signature } });
        fireEvent.click(screen.getByText('Verify'));
        expect((await screen.findByRole('alert')).textContent?.trim()).toBe('Signature is valid');
    });

    // a key whose base58 form has 43 characters: it is also valid unpadded base64, of a different key
    const AMBIGUOUS = {
        publicHex: '01234f729eae247bd3a22e12b33acfa9173d407c4ad8908c518503ce20a930b5',
        publicBase58: '5SdufKhMtY7dsJUnZ4nK3Ui15jpBChFo96g59mRqPAL',
        signatureHex:
            '095561c83b7874fe955072576fff9985d919b75b2d7799cad32f81842f3b0a748dc9c0bb315417b8106f7cbe393594b3f9fb1e236d98952a4f31e1c7cde25b0e',
    };

    it('asks which format to read an ambiguous key in, instead of guessing', async () => {
        render(<FormVerify publicKey={AMBIGUOUS.publicBase58} signature={AMBIGUOUS.signatureHex} message="ambiguous" />);
        fireEvent.click(screen.getByText('Verify'));
        expect(await screen.findByText('Public key: this text could be base64 or base58: pick the format.')).toBeInTheDocument();
        expect(screen.queryByText('Signature is valid')).not.toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Read as base58' })); // the right reading: verifies at once
        expect((await screen.findByRole('alert')).textContent?.trim()).toBe('Signature is valid');
        expect(screen.queryByText(/pick the format/)).not.toBeInTheDocument();
    });

    it('takes the other reading when asked to: another key, so the signature is wrong', async () => {
        render(<FormVerify publicKey={AMBIGUOUS.publicBase58} signature={AMBIGUOUS.signatureHex} message="ambiguous" />);
        fireEvent.click(screen.getByText('Verify'));
        fireEvent.click(await screen.findByRole('button', { name: 'Read as base64' }));
        expect((await screen.findByRole('alert')).textContent?.trim()).toBe('Signature is wrong');
    });

    it('forgets the pick when the key is edited', async () => {
        render(<FormVerify publicKey={AMBIGUOUS.publicBase58} signature={AMBIGUOUS.signatureHex} message="ambiguous" />);
        fireEvent.click(screen.getByText('Verify'));
        fireEvent.click(await screen.findByRole('button', { name: 'Read as base58' }));
        await screen.findByRole('alert');
        fireEvent.input(screen.getByLabelText('Public key'), { target: { value: AMBIGUOUS.publicBase58 } });
        fireEvent.click(screen.getByText('Verify'));
        expect(await screen.findByRole('button', { name: 'Read as base58' })).toBeInTheDocument(); // asked again
    });

    it('verifies with a key and a signature written in any of the formats', async () => {
        const publicKey = hexToBytes(AMBIGUOUS.publicHex);
        const signature = hexToBytes(AMBIGUOUS.signatureHex);
        const cases: [string, string, string][] = [
            ['hex', encodeAs(publicKey, 'hex'), encodeAs(signature, 'hex')],
            ['0x hex', encodeAs(publicKey, 'hex0x'), encodeAs(signature, 'hex0x')],
            ['base64', encodeAs(publicKey, 'base64'), encodeAs(signature, 'base64')],
            ['base64url', encodeAs(publicKey, 'base64url').replace(/=+$/, '') + '=', encodeAs(signature, 'base64url')],
            ['base58 signature', encodeAs(publicKey, 'hex'), encodeAs(signature, 'base58')],
            ['base32', encodeAs(publicKey, 'base32'), encodeAs(signature, 'base32')],
            ['byte array', encodeAs(publicKey, 'bytes'), encodeAs(signature, 'bytes')],
        ];
        for (const [name, key, sig] of cases) {
            const { unmount } = render(<FormVerify publicKey={key} signature={sig} message="ambiguous" />);
            fireEvent.click(screen.getByText('Verify'));
            expect((await screen.findByRole('alert')).textContent?.trim(), name).toBe('Signature is valid');
            unmount();
        }
    });

    describe('the format menus', () => {
        const SPKI_PEM =
            '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAX4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0=\n-----END PUBLIC KEY-----\n';
        const publicKeyField = () => screen.getByLabelText('Public key') as HTMLTextAreaElement;
        const signatureField = () => screen.getByLabelText('Signature') as HTMLTextAreaElement;

        it('are disabled, and say Auto, while a field is empty or not valid', () => {
            render(<FormVerify />);
            expect(formatButton('Public key format')).toBeDisabled();
            expect(formatButton('Public key format')).toHaveTextContent('Auto');
            fireEvent.input(publicKeyField(), { target: { value: 'not a key' } });
            expect(formatButton('Public key format')).toBeDisabled();
        });

        it('show the format that was recognised, with the size', () => {
            render(<FormVerify publicKey={AMBIGUOUS.publicBase58} signature={AMBIGUOUS.signatureHex} />);
            // 43 characters of base58: ambiguous, so nothing is claimed until the user picks
            expect(formatButton('Public key format')).toHaveTextContent('Auto');
            expect(formatButton('Signature format')).toHaveTextContent('Hex');
            expect(screen.getByText('Detected: hex · 64 bytes')).toBeInTheDocument();
        });

        it('rewrite the public key in the format picked, and it still verifies', async () => {
            render(<FormVerify publicKey={AMBIGUOUS.publicHex} signature={AMBIGUOUS.signatureHex} message="ambiguous" />);
            expect(screen.getByText('Detected: hex · 32 bytes')).toBeInTheDocument();

            pickFormat('Public key format', 'base64');
            expect(publicKeyField().value).toBe('ASNPcp6uJHvToi4SszrPqRc9QHxK2JCMUYUDziCpMLU=');
            expect(formatButton('Public key format')).toHaveTextContent('Base64');
            expect(screen.getByText('Detected: base64 · 32 bytes')).toBeInTheDocument();

            pickFormat('Public key format', 'bytes');
            expect(publicKeyField().value).toMatch(/^\[1, 35, 79, 114/);
            fireEvent.click(screen.getByText('Verify'));
            expect((await screen.findByRole('alert')).textContent?.trim()).toBe('Signature is valid');
        });

        it('rewrite the signature too', () => {
            render(<FormVerify publicKey={AMBIGUOUS.publicHex} signature={AMBIGUOUS.signatureHex} />);
            pickFormat('Signature format', 'base58');
            expect(signatureField().value).toBe('BpkGf57zKwUt9zk7sw939Q3JBXQjwaN2ksfkp5Rkt16GZVHSnxUZrffJii6YgQ9uRzU1qjigsqZKovtk6jzrPHX');
            pickFormat('Signature format', 'hex');
            expect(signatureField().value).toBe(AMBIGUOUS.signatureHex);
        });

        it('turn a key file into a plain key', () => {
            render(<FormVerify publicKey={SPKI_PEM} />);
            expect(formatButton('Public key format')).toHaveTextContent('PEM');
            pickFormat('Public key format', 'hex');
            expect(publicKeyField().value).toBe('5f82d54a68d23979e9756866b6b90ce277ef34e1d5daec3871c5409d56351a8d');
        });

        it('never ask about what they wrote themselves, even a 43-character base58 key', async () => {
            render(<FormVerify publicKey={AMBIGUOUS.publicHex} signature={AMBIGUOUS.signatureHex} message="ambiguous" />);
            pickFormat('Public key format', 'base58');
            expect(publicKeyField().value).toBe(AMBIGUOUS.publicBase58); // 43 characters: also valid base64, of another key
            fireEvent.click(screen.getByText('Verify'));
            expect((await screen.findByRole('alert')).textContent?.trim()).toBe('Signature is valid');
            expect(screen.queryByText(/pick the format/)).not.toBeInTheDocument();
        });

        it('forget what they wrote as soon as the text is edited', async () => {
            render(<FormVerify publicKey={AMBIGUOUS.publicHex} signature={AMBIGUOUS.signatureHex} message="ambiguous" />);
            pickFormat('Public key format', 'base58');
            fireEvent.input(publicKeyField(), { target: { value: AMBIGUOUS.publicBase58 } }); // the same text, typed: now it is asked
            fireEvent.click(screen.getByText('Verify'));
            expect(await screen.findByText(/pick the format/)).toBeInTheDocument();
        });
    });
});
