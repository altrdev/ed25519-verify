import { fireEvent, render, screen } from '@testing-library/preact';
import App from '../App';

const open = () => fireEvent.click(screen.getByRole('button', { name: 'What is this?' }));

describe('the help dialog', () => {
    it('opens from the top bar, names itself and moves the focus into it', () => {
        render(<App />);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        open();
        const dialog = screen.getByRole('dialog', { name: 'What is this?' });
        expect(dialog).toHaveAttribute('aria-modal', 'true');
        expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus();
        expect(dialog).toHaveTextContent('nothing is uploaded');
        expect(dialog).toHaveTextContent('ssh-keygen -Y sign');
    });

    it.each([
        ['the close button', () => fireEvent.click(screen.getByRole('button', { name: 'Close' }))],
        ['Escape', () => fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })],
        ['a click outside', () => fireEvent.click(screen.getByRole('dialog').parentElement as HTMLElement)],
    ])('closes with %s and gives the focus back to the button that opened it', (_name, close) => {
        render(<App />);
        open();
        close();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'What is this?' })).toHaveFocus();
    });

    it('stays open for a click inside it', () => {
        render(<App />);
        open();
        fireEvent.click(screen.getByRole('heading', { name: 'What it does' }));
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
});
