import { fireEvent, render, screen, within } from '@testing-library/preact';
import App, { VersionLabel } from '../App';

describe('App', () => {
    it('switches between tabs and between verifying and creating without unmounting the forms', () => {
        render(<App />);
        const messageField = () =>
            screen.getAllByLabelText('Message', { selector: 'textarea' }).find((e) => !e.closest('[hidden]')) as HTMLTextAreaElement;
        fireEvent.input(messageField(), { target: { value: 'keep me' } });

        // the raw signature tab creates as well: the form of the signature is still there
        fireEvent.click(screen.getByRole('button', { name: 'Create a signature' }));
        expect(within(screen.getByRole('tabpanel')).getByLabelText('Private key')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Verify a signature' }));
        expect(messageField().value).toBe('keep me');

        fireEvent.click(screen.getByRole('tab', { name: 'Tokens and files' }));
        expect(within(screen.getByRole('tabpanel')).getByLabelText('Token')).toBeVisible();
        fireEvent.click(screen.getByRole('tab', { name: 'Raw signature' }));
        expect(messageField().value).toBe('keep me');
    });

    it('has two tabs, each with the same switch between verifying and creating', () => {
        render(<App />);
        expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual(['Raw signature', 'Tokens and files']);
        expect(
            within(screen.getByRole('group', { name: 'Action' }))
                .getAllByRole('button')
                .map((b) => b.textContent),
        ).toEqual(['Verify a signature', 'Create a signature']);
        fireEvent.click(screen.getByRole('tab', { name: 'Tokens and files' }));
        expect(
            within(screen.getByRole('group', { name: 'Action' }))
                .getAllByRole('button')
                .map((b) => b.textContent),
        ).toEqual(['Verify a signature', 'Create a signature']);
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
