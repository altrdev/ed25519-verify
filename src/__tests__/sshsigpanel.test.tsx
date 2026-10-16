import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { SSHSIG_EXAMPLES } from '../examples';
import FormSigned from '../FormSigned';
import { parseSshsigShare, sshsigShareFragment } from '../share';
import { MessageFormat } from '../enum';
import {
    SSH_FINGERPRINT,
    SSH_MESSAGE,
    SSH_PRIVATE,
    SSH_PUBLIC,
    SSH_SIG_FILE_SHA256,
    SSH_SIG_FILE_SHA512,
    SSH_SIG_GIT_SHA256,
} from './fixtures/sshsig';

// the fields of the format and the action that are showing (the others stay mounted, hidden)
const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name, exact: true }));
const useFormat = () =>
    fireEvent.click(within(screen.getByRole('group', { name: 'Signature format' })).getByRole('button', { name: 'SSH signature' }));
const useAction = (name: string) => fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name }));

describe('SSH signature tab, verifying', () => {
    beforeEach(() => {
        render(<FormSigned />);
        useFormat();
    });

    it('verifies a signature made by ssh-keygen with the key that is trusted, and says what it is for', async () => {
        type('Signature', SSH_SIG_FILE_SHA512);
        type('Message', SSH_MESSAGE);
        type('Public key you trust', SSH_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        const details = within(screen.getByRole('region', { name: 'Signature details' }));
        expect(details.getByText('file')).toBeInTheDocument();
        expect(details.getByText(`Key inside it: ${SSH_FINGERPRINT}`)).toBeInTheDocument();
        expect(details.getByText('Hash of the message: sha512')).toBeInTheDocument();
        expect(details.getByText('Message: 12 bytes')).toBeInTheDocument();
    });

    it('without a trusted key it does not say valid: it says for which key, and asks for it', async () => {
        type('Signature', SSH_SIG_GIT_SHA256);
        type('Message', SSH_MESSAGE);
        click('Verify');
        expect(await screen.findByText(/valid for the key inside it/)).toBeInTheDocument();
        expect(screen.queryByText('Signature is valid')).not.toBeInTheDocument();
        expect(screen.getAllByText(SSH_FINGERPRINT, { exact: false }).length).toBeGreaterThan(0);
    });

    it('refuses another key, and a namespace that is not the expected one, with the reason', async () => {
        type('Signature', SSH_SIG_FILE_SHA256);
        type('Message', SSH_MESSAGE);
        type('Public key you trust', '5f82d54a68d23979e9756866b6b90ce277ef34e1d5daec3871c5409d56351a8d');
        click('Verify');
        expect(await screen.findByText(/made by the key SHA256:.*not by the key you gave/)).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();

        type('Public key you trust', SSH_PUBLIC);
        type('Namespace (optional)', 'git');
        click('Verify');
        expect(await screen.findByText(/is for the namespace "file", not "git"/)).toBeInTheDocument();
    });

    it('says wrong for another message, and hints at a newline that was lost', async () => {
        type('Signature', SSH_SIG_FILE_SHA512);
        type('Message', 'hello world'); // the file had a newline at the end
        type('Public key you trust', SSH_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(await screen.findByText('It is valid with a newline added at the end of the message.')).toBeInTheDocument();
    });

    it('says what is wrong with a signature that cannot be read', async () => {
        type('Signature', 'not a signature');
        click('Verify');
        expect(await screen.findByText(/starts with "-----BEGIN SSH SIGNATURE-----"/)).toBeInTheDocument();
    });

    it('goes through the examples', async () => {
        const load = () =>
            fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        load();
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('Made by ssh-keygen -Y sign.')).toBeInTheDocument();
        load();
        await waitFor(() => expect(screen.getByText('A signature for git.')).toBeInTheDocument());
        await waitFor(() => expect(within(screen.getByRole('region', { name: 'Signature details' })).getByText('git')).toBeInTheDocument());
    });

    it('copies a link with the signature, the key, the namespace and a typed message; not with a file', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        type('Signature', SSH_SIG_FILE_SHA512);
        type('Message', SSH_MESSAGE);
        type('Public key you trust', SSH_PUBLIC);
        fireEvent.click(
            screen.getAllByRole('button', { name: 'Copy link to this verification' }).find((b) => !b.closest('[hidden]')) as HTMLElement,
        );
        await waitFor(() => expect(writeText).toHaveBeenCalled());
        const shared = parseSshsigShare(new URL(writeText.mock.calls[0][0]).hash);
        expect(shared).toMatchObject({ signature: SSH_SIG_FILE_SHA512.trim(), publicKey: SSH_PUBLIC, message: SSH_MESSAGE });
    });
});

describe('SSH signature tab, creating', () => {
    beforeEach(() => {
        render(<FormSigned />);
        useFormat();
        useAction('Create a signature');
    });

    it('gives byte for byte the signature of ssh-keygen, and the key to verify it', async () => {
        type('Private key', SSH_PRIVATE);
        type('Message', SSH_MESSAGE);
        click('Sign');
        const armored = await screen.findByText((_, element) => element?.tagName === 'PRE' && element.textContent === SSH_SIG_FILE_SHA512);
        expect(armored).toBeInTheDocument();
        expect(screen.getByText(SSH_FINGERPRINT)).toBeInTheDocument();
        expect(field('Public key to verify it').value).toBe(SSH_PUBLIC.split(' ').slice(0, 2).join(' '));
    });

    it('uses the namespace and the hash that are chosen, and refuses an empty namespace', async () => {
        type('Private key', SSH_PRIVATE);
        type('Message', SSH_MESSAGE);
        type('Namespace', 'git');
        fireEvent.click(screen.getByRole('button', { name: 'SHA-256' }));
        click('Sign');
        await screen.findByText((_, element) => element?.tagName === 'PRE' && element.textContent === SSH_SIG_GIT_SHA256);

        type('Namespace', '');
        click('Sign');
        expect(await screen.findByText(/namespace is required/)).toBeInTheDocument();
        type('Namespace', 'a b');
        click('Sign');
        expect(await screen.findByText(/spaces or commas/)).toBeInTheDocument();
    });

    it('reproduces the example, and says so', async () => {
        fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        click('Sign');
        expect(await screen.findByText('Identical to the signature made by ssh-keygen.')).toBeInTheDocument();
        type('Message', 'another message');
        click('Sign');
        await waitFor(() => expect(screen.queryByText('Identical to the signature made by ssh-keygen.')).not.toBeInTheDocument());
    });
});

describe('a link to an SSH signature', () => {
    afterEach(() => history.replaceState(null, '', '/'));

    it('opens the signed formats tab on the SSH signature, filled in and verified', async () => {
        const fragment = sshsigShareFragment({
            signature: SSH_SIG_FILE_SHA512,
            publicKey: SSH_PUBLIC,
            namespace: '',
            message: SSH_MESSAGE,
            messageFormat: MessageFormat.Text,
        });
        history.replaceState(null, '', `/${fragment}`);
        render(<App />);
        await waitFor(() => expect(within(screen.getByRole('tabpanel')).getByText('Signature is valid')).toBeInTheDocument());
        expect(SSHSIG_EXAMPLES).toHaveLength(2);
    });

    it('keeps the links of the other tabs apart', () => {
        expect(parseSshsigShare('#fmt=jws&token=a')).toBeNull();
        expect(parseSshsigShare('#pk=a&sig=b')).toBeNull();
        expect(sshsigShareFragment({ signature: '', publicKey: ' ', namespace: '', message: '', messageFormat: MessageFormat.Text })).toBe(
            '',
        );
    });
});
