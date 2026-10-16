import { render, screen, fireEvent } from '@testing-library/preact';
import FormSign from '../FormSign';

describe('FormSign component', () => {
    it('should render', () => {
        render(<FormSign />);
        expect(screen.getByLabelText('Private key')).toBeInTheDocument();
    });

    it('should render with error banner', async () => {
        render(<FormSign />);
        fireEvent.click(screen.getByText('Sign'));
        const alert = await screen.findByRole('alert');
        expect(alert.textContent?.trim()).toBe("Signature can't be performed. Private key is mandatory");
    });

    it('should render with valid banner', async () => {
        render(
            <FormSign
                message="000000001"
                privateKey="Au+pr7EwTqpNEGOMkz3s5RnDnunOnhDYCT0hjueZIXo="
            />
        );
        fireEvent.click(screen.getByText('Sign'));
        const alert = await screen.findByRole('alert');
        expect(alert.textContent).toContain('Signature:');
        expect(alert.textContent).toContain(
            '9as6qIjGsKt5L+m5vcJhMrN007oYMAQk4yUtZBeVQ3LRXWa99R2iStrXND9UWqkSeCfiKB55aO+aUYjMI6XvCQ=='
        );
    });

    it('should deduce the public key from the private key', async () => {
        render(<FormSign privateKey="" />);
        const input = screen.getByLabelText('Private key');
        fireEvent.input(input, { target: { value: '3WrwK5pNuYUbYeWeid1jr8+YJ5BIJ9bE5AoU7TpEXwERZ6w1rApJuqlpLg3Kjd7bYKonCPHScUS4Ufjrp8dRTg==' } });
        fireEvent.change(input);
        expect(await screen.findByDisplayValue('EWesNawKSbqpaS4Nyo3e22CqJwjx0nFEuFH466fHUU4=')).toBeInTheDocument();
    });
});
