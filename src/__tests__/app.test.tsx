import { render, screen, fireEvent } from '@testing-library/preact';
import App, { VersionLabel } from '../App';

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

    it('shows the version of the build', () => {
        render(<App />);
        expect(screen.getByText(__APP_VERSION__)).toBeInTheDocument();
    });

    it('links a release to its notes and shows any other build as it is', () => {
        const { rerender } = render(<VersionLabel version="2.6.0" />);
        const link = screen.getByRole('link', { name: 'v2.6.0' });
        expect(link).toHaveAttribute('href', 'https://github.com/altrdev/ed25519-verify/releases/tag/v2.6.0');
        rerender(<VersionLabel version="main-1a2b3c4" />);
        expect(screen.queryByRole('link')).not.toBeInTheDocument();
        expect(screen.getByText('main-1a2b3c4')).toBeInTheDocument();
        rerender(<VersionLabel version="dev" />);
        expect(screen.getByText('dev')).toBeInTheDocument();
    });

    it('links to the public GitHub repository', () => {
        render(<App />);
        const link = screen.getByRole('link', { name: 'View source on GitHub' });
        expect(link).toHaveAttribute('href', 'https://github.com/altrdev/ed25519-verify');
        expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
    });
});
