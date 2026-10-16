import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { hexToBytes } from '../bytes';
import { encodeMinisignPublic, parseKeyId } from '../minisign';
import { MessageFormat } from '../enum';
import { MINISIGN_EXAMPLES } from '../examples';
import FormSigned from '../FormSigned';
import { minisignShareFragment, parseMinisignShare } from '../share';
import {
    MS_KEY_ID,
    MS_MESSAGE,
    MS_PUBLIC_FILE,
    MS_PUBLIC_HEX,
    MS_PUBLIC_LINE,
    MS_SEED,
    MS_SIG_HASHED,
    MS_SIG_LEGACY,
} from './fixtures/minisign';

// the fields of the format and the action that are showing (the others stay mounted, hidden)
const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name, exact: true }));
const useFormat = () =>
    fireEvent.click(within(screen.getByRole('group', { name: 'Signature format' })).getByRole('button', { name: 'minisign' }));
const useAction = (name: string) => fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name }));
const region = () => within(screen.getByRole('region', { name: 'Signature details' }));

describe('minisign tab, verifying', () => {
    beforeEach(() => {
        render(<FormSigned />);
        useFormat();
    });

    it('verifies a signature made by minisign with its .pub file, and shows the comments for what they are', async () => {
        type('Signature', MS_SIG_HASHED);
        type('Message', MS_MESSAGE);
        type('Public key you trust', MS_PUBLIC_FILE);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(MS_KEY_ID)).toBeInTheDocument();
        expect(region().getByText(/Trusted comment \(signed, so it is authentic\): timestamp:1700000000/)).toBeInTheDocument();
        expect(region().getByText(/Untrusted comment \(not signed.*signature from minisign secret key/)).toBeInTheDocument();
        expect(region().getByText(/Form: ED, it signs the BLAKE2b-512 hash/)).toBeInTheDocument();
        expect(screen.getByText(`minisign public key, ID ${MS_KEY_ID}`)).toBeInTheDocument();
    });

    it('takes the key line alone, or the key in another format', async () => {
        type('Signature', MS_SIG_HASHED);
        type('Message', MS_MESSAGE);
        type('Public key you trust', MS_PUBLIC_LINE);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        type('Public key you trust', MS_PUBLIC_HEX);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
    });

    it('verifies the legacy form', async () => {
        type('Signature', MS_SIG_LEGACY);
        type('Message', MS_MESSAGE);
        type('Public key you trust', MS_PUBLIC_FILE);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(/Form: Ed \(legacy\)/)).toBeInTheDocument();
    });

    it('refuses a comment that was changed, even though the message is fine', async () => {
        type('Signature', MS_SIG_HASHED.replace('1700000000', '1700000001'));
        type('Message', MS_MESSAGE);
        type('Public key you trust', MS_PUBLIC_FILE);
        click('Verify');
        expect(await screen.findByText(/trusted comment is not the one that was signed/)).toBeInTheDocument();
        expect(screen.queryByText('Signature is valid')).not.toBeInTheDocument();
        expect(region().getByText(/does not match, do not rely on it/)).toBeInTheDocument();
    });

    it('asks for the key, and refuses another key with both IDs', async () => {
        type('Signature', MS_SIG_HASHED);
        type('Message', MS_MESSAGE);
        click('Verify');
        expect(await screen.findByText(/public key is needed/)).toBeInTheDocument();

        type('Public key you trust', encodeMinisignPublic({ keyId: parseKeyId('0000000000000001'), publicKey: hexToBytes(MS_PUBLIC_HEX) }));
        click('Verify');
        expect(
            await screen.findByText(/made by the key B74960C202F410C9, not by the key you gave \(0000000000000001\)/),
        ).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
    });

    it('says wrong for another message, and hints at a newline that was lost', async () => {
        type('Signature', MS_SIG_HASHED);
        type('Message', 'hello world');
        type('Public key you trust', MS_PUBLIC_FILE);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(await screen.findByText('It is valid with a newline added at the end of the message.')).toBeInTheDocument();
    });

    it('says what is wrong with a signature that cannot be read', async () => {
        type('Signature', 'not a signature');
        click('Verify');
        expect(await screen.findByText(/four lines/)).toBeInTheDocument();
    });

    it('goes through the examples', async () => {
        const load = () =>
            fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        load();
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('Made by minisign.')).toBeInTheDocument();
        load();
        await waitFor(() => expect(screen.getByText('A legacy signature.')).toBeInTheDocument());
        await waitFor(() => expect(region().getByText(/Form: Ed \(legacy\)/)).toBeInTheDocument());
    });

    it('copies a link with the signature, the key and a typed message', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        type('Signature', MS_SIG_HASHED);
        type('Message', MS_MESSAGE);
        type('Public key you trust', MS_PUBLIC_FILE);
        fireEvent.click(
            screen.getAllByRole('button', { name: 'Copy link to this verification' }).find((b) => !b.closest('[hidden]')) as HTMLElement,
        );
        await waitFor(() => expect(writeText).toHaveBeenCalled());
        const shared = parseMinisignShare(new URL(writeText.mock.calls[0][0]).hash);
        expect(shared).toMatchObject({ signature: MS_SIG_HASHED.trim(), publicKey: MS_PUBLIC_FILE.trim(), message: MS_MESSAGE });
    });
});

describe('minisign tab, creating', () => {
    beforeEach(() => {
        render(<FormSigned />);
        useFormat();
        useAction('Create a signature');
    });

    it('gives byte for byte the signature of minisign when given the key ID, and the .pub file', async () => {
        type('Private key', MS_SEED);
        type('Message', MS_MESSAGE);
        type('Trusted comment (optional)', 'timestamp:1700000000\tfile:msg.txt');
        type('Key ID (optional)', MS_KEY_ID);
        click('Sign');
        await screen.findByText((_, element) => element?.tagName === 'PRE' && element.textContent === MS_SIG_HASHED);
        expect(field('Public key to verify it').value).toBe(MS_PUBLIC_FILE);
    });

    it('makes a key ID by itself, and refuses a malformed one or a comment of two lines', async () => {
        type('Private key', MS_SEED);
        type('Message', MS_MESSAGE);
        click('Sign');
        await waitFor(() =>
            expect(field('Public key to verify it').value).toMatch(/^untrusted comment: minisign public key [0-9A-F]{16}\nRW/),
        );

        type('Key ID (optional)', 'xyz');
        click('Sign');
        expect(await screen.findByText(/16 hex digits/)).toBeInTheDocument();
        type('Key ID (optional)', '');
        type('Trusted comment (optional)', 'a\nb');
        click('Sign');
        expect(await screen.findByText(/one line/)).toBeInTheDocument();
    });

    it('reproduces the example, and says so', async () => {
        fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        click('Sign');
        expect(await screen.findByText('Identical to the signature made by minisign.')).toBeInTheDocument();
        type('Message', 'another message');
        click('Sign');
        await waitFor(() => expect(screen.queryByText('Identical to the signature made by minisign.')).not.toBeInTheDocument());
    });
});

describe('a link to a minisign verification', () => {
    afterEach(() => history.replaceState(null, '', '/'));

    it('opens the signed formats tab on minisign, filled in and verified', async () => {
        history.replaceState(
            null,
            '',
            `/${minisignShareFragment({ signature: MS_SIG_HASHED, publicKey: MS_PUBLIC_FILE, message: MS_MESSAGE, messageFormat: MessageFormat.Text })}`,
        );
        render(<App />);
        await waitFor(() => expect(within(screen.getByRole('tabpanel')).getByText('Signature is valid')).toBeInTheDocument());
        expect(MINISIGN_EXAMPLES).toHaveLength(2);
    });

    it('keeps the links of the other tabs apart', () => {
        expect(parseMinisignShare('#fmt=sshsig&sig=a')).toBeNull();
        expect(parseMinisignShare('#pk=a&sig=b')).toBeNull();
        expect(minisignShareFragment({ signature: '', publicKey: ' ', message: '', messageFormat: MessageFormat.Text })).toBe('');
    });
});
