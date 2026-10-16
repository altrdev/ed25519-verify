import { fireEvent, render, screen, within } from '@testing-library/preact';
import FormatMenu from '../FormatMenu';

const setup = (props: Partial<Parameters<typeof FormatMenu>[0]> = {}) => {
    const onSelect = vi.fn();
    render(
        <div>
            <FormatMenu name="Public key format" label="Base58" current="base58" onSelect={onSelect} {...props} />
            <button>elsewhere</button>
        </div>
    );
    return { onSelect, button: () => screen.getByRole('button', { name: 'Public key format: Base58' }) };
};

describe('FormatMenu', () => {
    it('shows the current format on a closed button', () => {
        const { button } = setup();
        expect(button()).toHaveAttribute('aria-haspopup', 'menu');
        expect(button()).toHaveAttribute('aria-expanded', 'false');
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    });

    it('opens a menu of every encoding, with the current one ticked', () => {
        const { button } = setup();
        fireEvent.click(button());
        expect(button()).toHaveAttribute('aria-expanded', 'true');
        const items = within(screen.getByRole('menu', { name: 'Public key format' })).getAllByRole('menuitemradio');
        expect(items.map((item) => item.getAttribute('data-format'))).toEqual(['hex', 'hex0x', 'base64', 'base64url', 'base58', 'base32', 'bytes']);
        expect(items.filter((item) => item.getAttribute('aria-checked') === 'true').map((i) => i.getAttribute('data-format'))).toEqual(['base58']);
        expect(document.activeElement).toBe(items[4]);                       // the focus starts on the current one
    });

    it('reports the pick and closes', () => {
        const { button, onSelect } = setup();
        fireEvent.click(button());
        fireEvent.click(screen.getByRole('menuitemradio', { name: /^Base64url/ }));
        expect(onSelect).toHaveBeenCalledExactlyOnceWith('base64url');
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
        expect(document.activeElement).toBe(button());                       // and the focus goes back to the button
    });

    it('moves with the arrow keys, wrapping around, and closes with Escape', () => {
        const { button } = setup({ current: 'hex' });
        fireEvent.click(button());
        const menu = screen.getByRole('menu');
        const items = within(menu).getAllByRole('menuitemradio');
        expect(document.activeElement).toBe(items[0]);
        fireEvent.keyDown(menu, { key: 'ArrowUp' });
        expect(document.activeElement).toBe(items[6]);                       // from the first to the last
        fireEvent.keyDown(menu, { key: 'ArrowDown' });
        expect(document.activeElement).toBe(items[0]);
        fireEvent.keyDown(menu, { key: 'End' });
        expect(document.activeElement).toBe(items[6]);
        fireEvent.keyDown(menu, { key: 'Home' });
        expect(document.activeElement).toBe(items[0]);
        fireEvent.keyDown(menu, { key: 'Escape' });
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
        expect(document.activeElement).toBe(button());
    });

    it('closes when the pointer goes elsewhere, and on Tab', () => {
        const { button } = setup();
        fireEvent.click(button());
        fireEvent.mouseDown(screen.getByText('elsewhere'));
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
        fireEvent.click(button());
        fireEvent.keyDown(screen.getByRole('menu'), { key: 'Tab' });
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    });

    it('cannot be opened when disabled', () => {
        setup({ label: 'Auto', current: null, disabled: true });
        const button = screen.getByRole('button', { name: 'Public key format: Auto' });
        expect(button).toBeDisabled();
        fireEvent.click(button);
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    });

    it('closes by itself when it becomes disabled while open', () => {
        const props = { name: 'Public key format', label: 'Base58', current: 'base58' as const, onSelect: vi.fn() };
        const { rerender } = render(<FormatMenu {...props} />);
        fireEvent.click(screen.getByRole('button', { name: 'Public key format: Base58' }));
        expect(screen.getByRole('menu')).toBeInTheDocument();
        rerender(<FormatMenu {...props} label="Auto" current={null} disabled />);
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    });
});
