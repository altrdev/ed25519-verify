import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { COSE_DETACHED, COSE_PUBLIC } from './fixtures/cose';
import { JWS_EXAMPLES, MINISIGN_EXAMPLES, PGP_EXAMPLES, SSHSIG_EXAMPLES } from '../examples';

// the Verify tab is showing: its fields (the others stay mounted, hidden)
const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const tab = (name: string) => screen.getByRole('tab', { name });
const open = () => fireEvent.click(screen.getByRole('button', { name: 'Open in Tokens and files' }));

describe('a container pasted in the Verify tab', () => {
    it('is named, and opens in the tab that reads it with the key, verified at once', async () => {
        render(<App />);
        type('Signature', JWS_EXAMPLES[0].token);
        expect(screen.getByText('This is a JWS / JWT token, not a plain signature.')).toBeInTheDocument();
        type('Public key', JWS_EXAMPLES[0].publicKey);
        open();
        expect(tab('Tokens and files')).toHaveAttribute('aria-selected', 'true');
        await waitFor(() =>
            expect(within(screen.getByRole('tabpanel', { hidden: false })).getByText('Signature is valid')).toBeInTheDocument(),
        );
        expect(field('Token').value).toBe(JWS_EXAMPLES[0].token);
        expect(field('Public key').value).toBe(JWS_EXAMPLES[0].publicKey);
    });

    it.each([
        ['an SSH signature', SSHSIG_EXAMPLES[0].signature, SSHSIG_EXAMPLES[0].publicKey, SSHSIG_EXAMPLES[0].message, 'SSH signature'],
        ['a minisign signature', MINISIGN_EXAMPLES[0].signature, MINISIGN_EXAMPLES[0].publicKey, MINISIGN_EXAMPLES[0].message, 'minisign'],
        ['an OpenPGP signature', PGP_EXAMPLES[0].signature, PGP_EXAMPLES[0].publicKey, PGP_EXAMPLES[0].message, 'OpenPGP'],
    ])('%s: the signature, the key and the message go to its fields and it is verified', async (name, signature, key, message, button) => {
        render(<App />);
        type('Signature', signature);
        type('Public key', key);
        type('Message', message);
        expect(screen.getByText(`This is ${name}, not a plain signature.`)).toBeInTheDocument();
        open();
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByRole('button', { name: button, exact: true })).toHaveAttribute('aria-pressed', 'true');
        expect(field('Message').value).toBe(message);
    });

    it('a COSE message: the message of the Verify tab becomes the payload that travels apart', async () => {
        render(<App />);
        type('Signature', COSE_DETACHED);
        type('Public key', COSE_PUBLIC);
        type('Message', 'hello world');
        expect(screen.getByText('This is a COSE message, not a plain signature.')).toBeInTheDocument();
        open();
        await waitFor(() => expect(screen.getByRole('button', { name: 'COSE', exact: true })).toHaveAttribute('aria-pressed', 'true'));
        expect(field('Payload').value).toBe('hello world');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
    });

    it('a file chosen as the message goes along', async () => {
        render(<App />);
        type('Signature', SSHSIG_EXAMPLES[0].signature);
        type('Public key', SSHSIG_EXAMPLES[0].publicKey);
        const picker = document.querySelector('input[type=file][aria-label="Message file"]') as HTMLInputElement;
        const file = new File(['hello world\n'], 'hello.txt');
        Object.defineProperty(picker, 'files', { value: [file], configurable: true });
        fireEvent.change(picker);
        await screen.findByText(/hello\.txt · 12 bytes/);
        open();
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getAllByText(/hello\.txt · 12 bytes/).length).toBeGreaterThan(0);
    });

    it('says nothing for a plain signature, and the button goes away when the text changes', () => {
        render(<App />);
        type('Signature', 'a'.repeat(128));
        expect(screen.queryByText(/not a plain signature/)).not.toBeInTheDocument();
        type('Signature', JWS_EXAMPLES[0].token);
        expect(screen.getByRole('button', { name: 'Open in Tokens and files' })).toBeInTheDocument();
        type('Signature', 'a'.repeat(128));
        expect(screen.queryByRole('button', { name: 'Open in Tokens and files' })).not.toBeInTheDocument();
    });

    it('opening a second time replaces what the tab held', async () => {
        render(<App />);
        type('Signature', JWS_EXAMPLES[0].token);
        type('Public key', JWS_EXAMPLES[0].publicKey);
        open();
        fireEvent.click(tab('Raw signature'));
        type('Signature', JWS_EXAMPLES[1].token);
        open();
        await waitFor(() => expect(field('Token').value).toBe(JWS_EXAMPLES[1].token));
    });
});
