import { render, screen, fireEvent, within } from '@testing-library/preact';
import { encodingDefault } from '../store';
import { SignEncoding } from '../enum';
import FormSign from '../FormSign';

const messageFormat = (name: string) =>
    within(screen.getByRole('group', { name: 'Message format' })).getByRole('button', { name });

const privateKey = "Au+pr7EwTqpNEGOMkz3s5RnDnunOnhDYCT0hjueZIXo=";
const expectedSignature = "9as6qIjGsKt5L+m5vcJhMrN007oYMAQk4yUtZBeVQ3LRXWa99R2iStrXND9UWqkSeCfiKB55aO+aUYjMI6XvCQ==";

describe('FormSign component', () => {
    beforeEach(() => {
        encodingDefault.value = SignEncoding.Base64;
    });

    it('should render', () => {
        render(<FormSign />);
        expect(screen.getByLabelText('Private key')).toBeInTheDocument();
    });

    it('should ask for the private key when it is missing', async () => {
        render(<FormSign />);
        fireEvent.click(screen.getByText('Sign'));
        expect(await screen.findByText('Private key is required.')).toBeInTheDocument();
        expect(screen.queryByText('Signature:')).not.toBeInTheDocument();
    });

    it('should explain a malformed private key, on blur and on Sign', async () => {
        render(<FormSign />);
        const input = screen.getByLabelText('Private key');
        fireEvent.input(input, { target: { value: 'abc' } });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument(); // no nagging while typing
        fireEvent.change(input);
        expect(await screen.findByText(/Private key is not valid base64\.|Private key: expected 32 bytes/)).toBeInTheDocument();

        fireEvent.input(input, { target: { value: privateKey } });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('should render with valid banner', async () => {
        render(<FormSign message="000000001" privateKey={privateKey} />);
        fireEvent.click(screen.getByText('Sign'));
        const alert = await screen.findByRole('alert');
        expect(alert.textContent).toContain('Signature:');
        expect(alert.textContent).toContain(expectedSignature);
    });

    it('should deduce the public key as the private key is typed', async () => {
        render(<FormSign />);
        fireEvent.input(screen.getByLabelText('Private key'), {
            target: { value: '3WrwK5pNuYUbYeWeid1jr8+YJ5BIJ9bE5AoU7TpEXwERZ6w1rApJuqlpLg3Kjd7bYKonCPHScUS4Ufjrp8dRTg==' },
        });
        expect(await screen.findByDisplayValue('EWesNawKSbqpaS4Nyo3e22CqJwjx0nFEuFH466fHUU4=')).toBeInTheDocument();
    });

    it('should deduce the public key of an initial private key', async () => {
        render(<FormSign privateKey={privateKey} />);
        expect(await screen.findByDisplayValue('X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0=')).toBeInTheDocument();
    });

    it('should drop a stale signature when the message changes', async () => {
        render(<FormSign message="000000001" privateKey={privateKey} />);
        fireEvent.click(screen.getByText('Sign'));
        await screen.findByRole('alert');
        fireEvent.input(screen.getByLabelText('Message'), { target: { value: 'other' } });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('should generate a key pair, reveal the private key and show the public key', async () => {
        render(<FormSign />);
        const input = screen.getByLabelText('Private key') as HTMLTextAreaElement;
        expect(input.value).toBe('');

        fireEvent.click(screen.getByRole('button', { name: /Generate/ }));
        await screen.findByRole('button', { name: 'Hide private key' });
        expect(input).not.toHaveClass('masked');
        expect(input.value).toMatch(/^[A-Za-z0-9+/]{43}=$/); // 32 bytes in base64

        const publicKey = screen.getByLabelText('Deduced Public key') as HTMLTextAreaElement;
        expect(publicKey.value).toMatch(/^[A-Za-z0-9+/]{43}=$/);

        fireEvent.input(screen.getByLabelText('Message'), { target: { value: 'hi' } });
        fireEvent.click(screen.getByText('Sign'));
        expect((await screen.findByRole('alert')).textContent).toContain('Signature:');
    });

    it('should generate hex keys when hex is selected', async () => {
        encodingDefault.value = SignEncoding.Hex;
        render(<FormSign />);
        fireEvent.click(screen.getByRole('button', { name: /Generate/ }));
        await screen.findByRole('button', { name: 'Hide private key' });
        expect((screen.getByLabelText('Private key') as HTMLTextAreaElement).value).toMatch(/^[0-9a-f]{64}$/);
    });

    it('masks the private key until it is revealed', () => {
        render(<FormSign privateKey="secret" />);
        const input = screen.getByLabelText('Private key');
        expect(input).toHaveClass('masked');
        fireEvent.click(screen.getByRole('button', { name: 'Show private key' }));
        expect(input).not.toHaveClass('masked');
        fireEvent.click(screen.getByRole('button', { name: 'Hide private key' }));
        expect(input).toHaveClass('masked');
    });

    it('copies the signature to the clipboard', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        render(<FormSign message="000000001" privateKey={privateKey} />);
        fireEvent.click(screen.getByText('Sign'));
        await screen.findByRole('alert');
        fireEvent.click(screen.getByRole('button', { name: 'Copy signature' }));
        expect(writeText).toHaveBeenCalledWith(expectedSignature);
        expect(await screen.findByText('Copied')).toBeInTheDocument();
    });

    it('signs a message given as hex or base64 exactly like the same text', async () => {
        // "000000001" as UTF-8 bytes
        const asHex = '303030303030303031';
        const asBase64 = 'MDAwMDAwMDAx';
        for (const [format, value] of [['Hex', asHex], ['Base64', asBase64]]) {
            const { unmount } = render(<FormSign privateKey={privateKey} />);
            fireEvent.click(messageFormat(format));
            fireEvent.input(screen.getByLabelText('Message'), { target: { value } });
            fireEvent.click(screen.getByText('Sign'));
            expect((await screen.findByRole('alert')).textContent).toContain(expectedSignature);
            unmount();
        }
    });

    it('explains a message that is not valid in the selected format, and clears it when the format changes', async () => {
        render(<FormSign privateKey={privateKey} message="not hex!" />);
        fireEvent.click(messageFormat('Hex'));
        fireEvent.click(screen.getByText('Sign'));
        expect(await screen.findByText('Message is not valid hex.')).toBeInTheDocument();
        expect(screen.getByLabelText('Message')).toHaveAttribute('aria-invalid', 'true');
        expect(screen.queryByText('Signature:')).not.toBeInTheDocument();

        fireEvent.click(messageFormat('Text'));
        expect(screen.queryByText('Message is not valid hex.')).not.toBeInTheDocument();
        fireEvent.click(screen.getByText('Sign'));
        expect((await screen.findByRole('alert')).textContent).toContain('Signature:');
    });

    it('drops a stale signature when the message format changes', async () => {
        render(<FormSign message="3030" privateKey={privateKey} />);
        fireEvent.click(screen.getByText('Sign'));
        await screen.findByRole('alert');
        fireEvent.click(messageFormat('Hex'));
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
});

describe('FormSign with keys in other formats', () => {
    const PKCS8_PEM = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIALvqa+xME6qTRBjjJM97OUZw57pzp4Q2Ak9IY7nmSF6\n-----END PRIVATE KEY-----\n';
    const JWK = '{"kty":"OKP","crv":"Ed25519","d":"Au-pr7EwTqpNEGOMkz3s5RnDnunOnhDYCT0hjueZIXo","x":"X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0"}';

    beforeEach(() => {
        encodingDefault.value = SignEncoding.Base64;
    });

    it('signs with a PKCS#8 PEM key, deduces the public key and shows the detected format', async () => {
        render(<FormSign privateKey={PKCS8_PEM} message="000000001" />);
        expect(screen.getByText('Detected format: PEM (PKCS#8)')).toBeInTheDocument();
        expect(await screen.findByDisplayValue('X4LVSmjSOXnpdWhmtrkM4nfvNOHV2uw4ccVAnVY1Go0=')).toBeInTheDocument();
        fireEvent.click(screen.getByText('Sign'));
        expect((await screen.findByRole('alert')).textContent).toContain(expectedSignature);
    });

    it('signs with a JWK exactly like with the same key as plain base64', async () => {
        render(<FormSign privateKey={JWK} message="000000001" />);
        fireEvent.click(screen.getByText('Sign'));
        expect((await screen.findByRole('alert')).textContent).toContain(expectedSignature);
    });

    it('says why an encrypted or foreign private key cannot be used', async () => {
        const encrypted = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----';
        render(<FormSign privateKey={encrypted} message="x" />);
        fireEvent.click(screen.getByText('Sign'));
        expect(await screen.findByText(/Private key: the key is encrypted with a passphrase/)).toBeInTheDocument();
        expect(screen.queryByText('Signature:')).not.toBeInTheDocument();
    });

    it('does not announce a format for plain hex or base64', () => {
        render(<FormSign privateKey={privateKey} />);
        expect(screen.queryByText(/^Detected format/)).not.toBeInTheDocument();
    });
});
