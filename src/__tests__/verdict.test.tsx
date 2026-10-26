import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import FormVerify from '../FormVerify';

const pill = () => document.querySelector('.pill');
const scroll = vi.fn();

beforeEach(() => {
    scroll.mockClear();
    // jsdom has no layout: every element is at 0, 0, which is "not in view" for the top bar
    Element.prototype.scrollIntoView = scroll;
});

describe('the verdict beside the Verify button and in view', () => {
    it('shows a pill next to the button, and brings the verdict into view', async () => {
        render(<FormVerify />);
        fireEvent.click(screen.getByRole('button', { name: 'Load example' }));
        await waitFor(() => expect(pill()).toHaveTextContent('Valid'));
        expect(pill()).toHaveClass('success');
        expect(pill()?.previousElementSibling).toBe(screen.getByRole('button', { name: 'Verify' }));
        expect(scroll).toHaveBeenCalledTimes(1);
    });

    it('says wrong, takes the pill back when an input changes, and scrolls again for the same answer', async () => {
        render(<FormVerify />);
        fireEvent.click(screen.getByRole('button', { name: 'Load example' }));
        await waitFor(() => expect(pill()).toHaveTextContent('Valid'));

        fireEvent.input(screen.getByLabelText('Signature'), { target: { value: `${'0'.repeat(127)}1` } });
        expect(pill()).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
        await waitFor(() => expect(pill()).toHaveTextContent('Wrong'));
        expect(pill()).toHaveClass('error');
        scroll.mockClear();

        fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
        await waitFor(() => expect(scroll).toHaveBeenCalledTimes(1));
        expect(pill()).toHaveTextContent('Wrong');
    });

    it('does not scroll for a verification the reader did not ask for (a share link)', async () => {
        render(
            <FormVerify
                autoVerify
                publicKey="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
                signature={`${'0'.repeat(127)}1`}
                message="72"
            />,
        );
        await waitFor(() => expect(pill()).toHaveTextContent('Wrong'));
        expect(scroll).not.toHaveBeenCalled();
    });

    it('keeps the pill out of what a screen reader is told: the banner is announced', async () => {
        render(<FormVerify />);
        fireEvent.click(screen.getByRole('button', { name: 'Load example' }));
        await waitFor(() => expect(pill()).toHaveAttribute('aria-hidden', 'true'));
        expect(screen.getByRole('alert')).toHaveTextContent('Signature is valid');
    });
});
