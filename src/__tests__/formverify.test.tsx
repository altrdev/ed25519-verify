import { render, screen, fireEvent } from '@testing-library/preact';
import FormVerify from '../FormVerify';

describe('FormVerify component', () => {
    it('should render', () => {
        render(<FormVerify />);
        expect(screen.getByLabelText('Public key')).toBeInTheDocument();
    });

    it('should render with error banner', async () => {
        render(<FormVerify />);
        fireEvent.click(screen.getByText('Verify'));
        const alert = await screen.findByRole('alert');
        expect(alert.textContent?.trim()).toBe('Signature is wrong');
    });

    it('should render with valid banner', async () => {
        render(
            <FormVerify
                message="000000102"
                signature="BhqKbhnVH3kaNARj/Vht7ImJJ2LMM5TOla7k5OTITjdZ+GpWTY69wH79vRowPmq0c2KFDNipPsUcXSAwrviqDA=="
                publicKey="u6xMxXSXi/dL9tWPS+qfxiOHMA6c2Czwh/k2hy/wx/U="
            />
        );
        fireEvent.click(screen.getByText('Verify'));
        const alert = await screen.findByRole('alert');
        expect(alert.textContent?.trim()).toBe('Signature is valid');
    });

    it('should hide the result when an input changes', async () => {
        render(<FormVerify />);
        fireEvent.click(screen.getByText('Verify'));
        await screen.findByRole('alert');
        fireEvent.input(screen.getByLabelText('Message'), { target: { value: 'changed' } });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
});
