import { render, screen, fireEvent } from '@testing-library/preact';
import { encodingDefault } from '../store';
import { SignEncoding } from '../enum';
import FormVerify from '../FormVerify';

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
});
