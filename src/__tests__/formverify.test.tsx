import { render, screen, fireEvent, within } from '@testing-library/preact';
import { encodingDefault } from '../store';
import { SignEncoding } from '../enum';
import FormVerify from '../FormVerify';

const messageFormat = (name: string) =>
    within(screen.getByRole('group', { name: 'Message format' })).getByRole('button', { name });

const signature = "BhqKbhnVH3kaNARj/Vht7ImJJ2LMM5TOla7k5OTITjdZ+GpWTY69wH79vRowPmq0c2KFDNipPsUcXSAwrviqDA==";
const publicKey = "u6xMxXSXi/dL9tWPS+qfxiOHMA6c2Czwh/k2hy/wx/U=";

describe('FormVerify component', () => {
    beforeEach(() => {
        encodingDefault.value = SignEncoding.Base64;
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
        expect(await screen.findByText(/Public key: expected 32 bytes, got 3\./)).toBeInTheDocument();
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
        for (const [format, value] of [['Hex', '303030303030313032'], ['Base64', 'MDAwMDAwMTAy']]) {
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
        encodingDefault.value = SignEncoding.Hex;
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
    const SIGNATURE_HEX = 'f5ab3aa888c6b0ab792fe9b9bdc26132b374d3ba18300424e3252d6417954372d15d66bdf51da24adad7343f545aa9127827e2281e7968ef9a5188cc23a5ef09';

    beforeEach(() => {
        encodingDefault.value = SignEncoding.Hex;
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
        expect(screen.getByLabelText('Public key')).toHaveAttribute('rows', '8');   // capped
    });
});
