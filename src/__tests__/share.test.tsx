import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import * as ed from '@noble/ed25519';
import App from '../App';
import FormVerify from '../FormVerify';
import { MessageFormat } from '../enum';
import { bytesToHex } from '../bytes';
import { parseShareFragment, shareFragment } from '../share';
import { setFormats } from './helpers';
import { PUBLIC_HEX, SEED_HEX } from './fixtures/keys';
import { hexToBytes } from '../bytes';

const roundTrip = (message: string, messageFormat = MessageFormat.Text) => {
    const fragment = shareFragment({ publicKey: PUBLIC_HEX, message, messageFormat, signature: 'abcd' });
    return parseShareFragment(fragment);
};

describe('share fragment', () => {
    it('carries the three fields and the message format', () => {
        const parsed = roundTrip('hello', MessageFormat.Hex);
        expect(parsed).toEqual({ publicKey: PUBLIC_HEX, message: 'hello', messageFormat: 'hex', signature: 'abcd' });
        expect(shareFragment({ publicKey: PUBLIC_HEX, message: 'hi', messageFormat: MessageFormat.Text, signature: 'x' })).not.toContain(
            'mf=',
        );
    });

    it('keeps any message intact: separators, newlines, unicode, spaces at the edges', () => {
        for (const message of ['a&b=c#d?e', 'line 1\nline 2\r\n', 'zażółć 🔑 日本語', '  padded  ', '100% + more', '%41']) {
            expect(roundTrip(message)?.message).toBe(message);
        }
    });

    it('is empty when there is nothing to share, and ignores other fragments', () => {
        expect(shareFragment({ publicKey: ' ', message: '', messageFormat: MessageFormat.Text, signature: '' })).toBe('');
        expect(parseShareFragment('')).toBeNull();
        expect(parseShareFragment('#section')).toBeNull();
        expect(parseShareFragment('#x=1&y=2')).toBeNull();
    });

    it('falls back to text for an unknown message format and takes partial links', () => {
        expect(parseShareFragment('#pk=ab&mf=nonsense')).toEqual({ publicKey: 'ab', messageFormat: 'text' });
    });
});

describe('share links in the app', () => {
    beforeEach(() => {
        setFormats('hex');
        history.replaceState(null, '', '/');
    });
    afterEach(() => history.replaceState(null, '', '/'));

    // the visible tab only: the forms of the other tabs stay mounted
    const value = (label: string) =>
        (within(screen.getByRole('tabpanel')).getByLabelText(label, { selector: 'textarea' }) as HTMLTextAreaElement).value;

    it('opens a link with the fields filled in and the answer shown', async () => {
        const signature = bytesToHex(await ed.signAsync(new TextEncoder().encode('shared message'), hexToBytes(SEED_HEX)));
        history.replaceState(null, '', `/#${new URLSearchParams({ pk: PUBLIC_HEX, msg: 'shared message', sig: signature })}`);
        render(<App />);
        expect(value('Public key')).toBe(PUBLIC_HEX);
        expect(screen.getAllByLabelText('Message', { selector: 'textarea' })[0]).toHaveValue('shared message');
        expect(value('Signature')).toBe(signature);
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
    });

    it('does not check a link that lacks the signature', () => {
        history.replaceState(null, '', `/#pk=${PUBLIC_HEX}`);
        render(<App />);
        expect(value('Public key')).toBe(PUBLIC_HEX);
        expect(screen.queryByText(/Signature is/)).not.toBeInTheDocument();
    });

    it('copies a link to what is in the form, never a private key', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        render(<FormVerify publicKey={PUBLIC_HEX} message="m&m" signature="abcd" />);
        fireEvent.click(screen.getByRole('button', { name: 'Copy link to this verification' }));
        await waitFor(() => expect(writeText).toHaveBeenCalled());
        const link = new URL(writeText.mock.calls[0][0]);
        expect(parseShareFragment(link.hash)).toEqual({ publicKey: PUBLIC_HEX, message: 'm&m', signature: 'abcd', messageFormat: 'text' });
        expect(link.hash).not.toContain(SEED_HEX);
    });

    it('has nothing to copy while the form is empty', () => {
        render(<FormVerify />);
        expect(screen.getByRole('button', { name: 'Copy link to this verification' })).toBeDisabled();
    });
});
