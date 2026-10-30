import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { MessageFormat } from '../enum';
import { SIGNIFY_EXAMPLES } from '../examples';
import FormSigned from '../FormSigned';
import { parseSignifyShare, signifyShareFragment } from '../share';
import { encodeSignifyPublic, parseKeyNumber } from '../signify';
import { hexToBytes } from '../bytes';
import { MS_SIG_HASHED } from './fixtures/minisign';
import { SG_KEY_NUMBER, SG_MESSAGE, SG_PUBLIC_FILE, SG_PUBLIC_HEX, SG_PUBLIC_LINE, SG_SEED, SG_SIG } from './fixtures/signify';

// the fields of the format and the action that are showing (the others stay mounted, hidden)
const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name }));
const useAction = (name: string) => fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name }));
const region = () => within(screen.getByRole('region', { name: 'Signature details' }));

describe('signify tab, verifying', () => {
    beforeEach(() => {
        render(<FormSigned format="signify" />);
    });

    it('verifies a signature made by signify with its .pub file, and shows the comment for what it is', async () => {
        type('Signature', SG_SIG);
        type('Message', SG_MESSAGE);
        type('Public key you trust', SG_PUBLIC_FILE);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(SG_KEY_NUMBER)).toBeInTheDocument();
        expect(region().getByText(/Untrusted comment \(not signed.*verify with signify.pub/)).toBeInTheDocument();
        expect(screen.getByText(`signify public key, key number ${SG_KEY_NUMBER}`)).toBeInTheDocument();
    });

    it('takes the key line alone, or the key in another format', async () => {
        type('Signature', SG_SIG);
        type('Message', SG_MESSAGE);
        type('Public key you trust', SG_PUBLIC_LINE);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        type('Public key you trust', SG_PUBLIC_HEX);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
    });

    it('asks for the key, and refuses another key with both numbers', async () => {
        type('Signature', SG_SIG);
        type('Message', SG_MESSAGE);
        click('Verify');
        expect(await screen.findByText(/public key is needed/)).toBeInTheDocument();

        type(
            'Public key you trust',
            encodeSignifyPublic({ keyNumber: parseKeyNumber('0000000000000001'), publicKey: hexToBytes(SG_PUBLIC_HEX) }),
        );
        click('Verify');
        expect(await screen.findByText(/key number 137a6ab64cfb746b, not by the key you gave \(0000000000000001\)/)).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
    });

    it('says wrong for another message, and hints at a newline that was lost', async () => {
        type('Signature', SG_SIG);
        type('Message', 'hello world');
        type('Public key you trust', SG_PUBLIC_FILE);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(await screen.findByText('It is valid with a newline added at the end of the message.')).toBeInTheDocument();
    });

    it('says what is wrong with a signature that cannot be read, and points a minisign one to its tab', async () => {
        type('Signature', 'not a signature');
        click('Verify');
        expect(await screen.findByText(/not valid base64/)).toBeInTheDocument();
        type('Signature', 'untrusted comment: x');
        click('Verify');
        expect(await screen.findByText(/two lines/)).toBeInTheDocument();
        type('Signature', MS_SIG_HASHED);
        click('Verify');
        expect(await screen.findByText(/it is a minisign signature/)).toBeInTheDocument();
    });

    it('goes through the example', async () => {
        fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('Made by signify.')).toBeInTheDocument();
    });

    it('copies a link with the signature, the key and a typed message', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        type('Signature', SG_SIG);
        type('Message', SG_MESSAGE);
        type('Public key you trust', SG_PUBLIC_FILE);
        fireEvent.click(
            screen.getAllByRole('button', { name: 'Copy link to this verification' }).find((b) => !b.closest('[hidden]')) as HTMLElement,
        );
        await waitFor(() => expect(writeText).toHaveBeenCalled());
        const shared = parseSignifyShare(new URL(writeText.mock.calls[0][0]).hash);
        expect(shared).toMatchObject({ signature: SG_SIG.trim(), publicKey: SG_PUBLIC_FILE.trim(), message: SG_MESSAGE });
    });
});

describe('signify tab, creating', () => {
    beforeEach(() => {
        render(<FormSigned format="signify" />);
        useAction('Create a signature');
    });

    it('gives byte for byte the signature of signify when given the key number, and the .pub file', async () => {
        type('Private key', SG_SEED);
        type('Message', SG_MESSAGE);
        type('Key number (optional)', SG_KEY_NUMBER);
        click('Sign');
        await screen.findByText(
            (_, element) => element?.tagName === 'PRE' && element.textContent?.split('\n')[1] === SG_SIG.split('\n')[1],
        );
        expect(field('Public key to verify it').value).toBe(SG_PUBLIC_FILE);
    });

    it('makes a key number by itself, and refuses a malformed one', async () => {
        type('Private key', SG_SEED);
        type('Message', SG_MESSAGE);
        click('Sign');
        await waitFor(() => expect(field('Public key to verify it').value).toMatch(/^untrusted comment: signify public key\nRW/));

        type('Key number (optional)', 'xyz');
        click('Sign');
        expect(await screen.findByText(/16 hexadecimal digits/)).toBeInTheDocument();
    });

    it('reproduces the example, and says so', async () => {
        fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        click('Sign');
        expect(await screen.findByText('Identical to the signature made by signify.')).toBeInTheDocument();
    });
});

describe('a link to a signify verification', () => {
    afterEach(() => history.replaceState(null, '', '/'));

    it('opens the signed formats tab on signify, filled in and verified', async () => {
        history.replaceState(
            null,
            '',
            `/${signifyShareFragment({ signature: SG_SIG, publicKey: SG_PUBLIC_FILE, message: SG_MESSAGE, messageFormat: MessageFormat.Text })}`,
        );
        render(<App />);
        await waitFor(() => expect(within(screen.getByRole('tabpanel')).getByText('Signature is valid')).toBeInTheDocument());
        expect(SIGNIFY_EXAMPLES).toHaveLength(1);
    });

    it('keeps the links of the other tabs apart', () => {
        expect(parseSignifyShare('#fmt=minisign&sig=a')).toBeNull();
        expect(parseSignifyShare('#pk=a&sig=b')).toBeNull();
    });
});
