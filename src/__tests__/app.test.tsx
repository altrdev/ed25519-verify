import { render, screen, fireEvent } from '@testing-library/preact';
import App from '../App';

describe('App', () => {
    it('switches between tabs without unmounting the forms', () => {
        render(<App />);
        // both forms are mounted: the first message field belongs to the verify tab
        const messageField = () => screen.getAllByLabelText('Message', { selector: 'textarea' })[0] as HTMLTextAreaElement;
        const verifyInput = messageField();
        fireEvent.input(verifyInput, { target: { value: 'keep me' } });

        fireEvent.click(screen.getByRole('tab', { name: 'Sign message' }));
        expect(screen.getByLabelText('Private key')).toBeVisible();

        fireEvent.click(screen.getByRole('tab', { name: 'Verify signature' }));
        expect(messageField().value).toBe('keep me');
    });

    it('toggles the theme and persists it', () => {
        render(<App />);
        fireEvent.click(screen.getByRole('button', { name: /switch to dark theme/i }));
        expect(document.documentElement.dataset.theme).toBe('dark');
        expect(localStorage.getItem('theme')).toBe('dark');
    });

    it('links to the public GitHub repository', () => {
        render(<App />);
        const link = screen.getByRole('link', { name: 'View source on GitHub' });
        expect(link).toHaveAttribute('href', 'https://github.com/altrdev/ed25519-verify');
        expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
    });
});
