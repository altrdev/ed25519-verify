import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { MessageFormat } from '../enum';
import { PGP_EXAMPLES } from '../examples';
import FormSigned from '../FormSigned';
import { parsePgpShare, pgpShareFragment } from '../share';
import {
    PGP_CLEARSIGNED,
    PGP_DETACHED_PRIMARY,
    PGP_DETACHED_SUB,
    PGP_MESSAGE,
    PGP_PRIMARY_FINGERPRINT,
    PGP_PUBLIC,
    PGP_SUBKEY_FINGERPRINT,
    PGP_V6_FINGERPRINT,
    PGP_V6_PUBLIC,
    PGP_V6_SIG,
} from './fixtures/openpgp';

// the fields of the format and the action that are showing (the others stay mounted, hidden)
const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name, exact: true }));
const useFormat = () =>
    fireEvent.click(within(screen.getByRole('group', { name: 'Signature format' })).getByRole('button', { name: 'OpenPGP' }));
const useAction = (name: string) => fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name }));
const region = () => within(screen.getByRole('region', { name: 'Signature details' }));
const spaced = (fingerprint: string) => fingerprint.replace(/(.{4})(?=.)/g, '$1 ');

describe('OpenPGP tab, verifying', () => {
    beforeEach(() => {
        render(<FormSigned />);
        useFormat();
    });

    it('verifies a signature made by gpg with the key block, finds the subkey that made it, and says what it holds', async () => {
        type('Signature', PGP_DETACHED_SUB);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(new RegExp(`Key: ${spaced(PGP_SUBKEY_FINGERPRINT)} \\(a subkey, version 4\\)`))).toBeInTheDocument();
        expect(region().getByText(/Fixture <fixture@example.com>/)).toBeInTheDocument();
        expect(region().getByText(/it is the message that was signed/)).toBeInTheDocument();
        expect(region().getByText(/EdDSA \(algorithm 22\), hash SHA-512/)).toBeInTheDocument();
        expect(region().getByText(/does not know whether the key is certified/)).toBeInTheDocument();
    });

    it('shows the primary key when it made the signature', async () => {
        type('Signature', PGP_DETACHED_PRIMARY);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_PUBLIC);
        click('Verify');
        await waitFor(() =>
            expect(region().getByText(new RegExp(`Key: ${spaced(PGP_PRIMARY_FINGERPRINT)} \\(the primary key`))).toBeInTheDocument(),
        );
    });

    it('verifies a cleartext signed message without a message, and refuses it when the text is changed', async () => {
        type('Signature', PGP_CLEARSIGNED);
        type('Public key you trust', PGP_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(/the text of the cleartext message/)).toBeInTheDocument();

        type('Signature', PGP_CLEARSIGNED.replace('line two', 'line 2'));
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(region().getByText(/is not the message that was signed/)).toBeInTheDocument();
    });

    it('verifies a version 6 signature with a version 6 key', async () => {
        type('Signature', PGP_V6_SIG);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_V6_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(new RegExp(`Key: ${spaced(PGP_V6_FINGERPRINT)}`))).toBeInTheDocument();
        expect(region().getByText(/version 6, Ed25519 \(algorithm 27\)/)).toBeInTheDocument();
    });

    it('says wrong for another message, and hints at a newline that was lost', async () => {
        type('Signature', PGP_DETACHED_SUB);
        type('Message', 'hello world');
        type('Public key you trust', PGP_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(await screen.findByText('It is valid with a newline added at the end of the message.')).toBeInTheDocument();
        expect(region().getByText(/is not the message that was signed/)).toBeInTheDocument();
    });

    it('refuses a key block that does not hold the key that made it, naming both, and never calls it wrong', async () => {
        type('Signature', PGP_DETACHED_SUB);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_V6_PUBLIC);
        click('Verify');
        expect(
            await screen.findByText(new RegExp(`made by the key ${spaced(PGP_SUBKEY_FINGERPRINT)}, which is not in the key block`)),
        ).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
    });

    it('asks for the key and the message, and says what is wrong with what cannot be read', async () => {
        type('Signature', PGP_DETACHED_SUB);
        click('Verify');
        expect(await screen.findByText(/public key is needed/)).toBeInTheDocument();
        expect(screen.getByText(/message the signature is for is needed/)).toBeInTheDocument();
        type('Signature', 'not a signature');
        click('Verify');
        expect(await screen.findByText(/Expected an armored block/)).toBeInTheDocument();
        type('Signature', PGP_PUBLIC);
        click('Verify');
        expect(await screen.findByText(/This is a public key, not a signature/)).toBeInTheDocument();
    });

    it('goes through the examples', async () => {
        const load = () =>
            fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        load();
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('Made by gpg --detach-sign.')).toBeInTheDocument();
        load();
        await waitFor(() => expect(screen.getByText('A cleartext signed message.')).toBeInTheDocument());
        await waitFor(() => expect(region().getByText(/the text of the cleartext message/)).toBeInTheDocument());
        load();
        await waitFor(() => expect(screen.getByText('A version 6 signature (RFC 9580).')).toBeInTheDocument());
        await waitFor(() => expect(region().getByText(/version 6, Ed25519/)).toBeInTheDocument());
    });

    it('copies a link with the signature, the key and a typed message', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        type('Signature', PGP_DETACHED_SUB);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_PUBLIC);
        fireEvent.click(
            screen.getAllByRole('button', { name: 'Copy link to this verification' }).find((b) => !b.closest('[hidden]')) as HTMLElement,
        );
        await waitFor(() => expect(writeText).toHaveBeenCalled());
        expect(parsePgpShare(new URL(writeText.mock.calls[0][0]).hash)).toMatchObject({
            signature: PGP_DETACHED_SUB.trim(),
            publicKey: PGP_PUBLIC.trim(),
            message: PGP_MESSAGE,
        });
    });

    it('does not offer to create a signature, and says why', () => {
        useAction('Create a signature');
        expect(screen.getByText(/Creating OpenPGP signatures is not offered here/)).toBeInTheDocument();
    });
});

describe('a link to an OpenPGP verification', () => {
    afterEach(() => history.replaceState(null, '', '/'));

    it('opens the signed formats tab on OpenPGP, filled in and verified', async () => {
        history.replaceState(
            null,
            '',
            `/${pgpShareFragment({ signature: PGP_DETACHED_SUB, publicKey: PGP_PUBLIC, message: PGP_MESSAGE, messageFormat: MessageFormat.Text })}`,
        );
        render(<App />);
        await waitFor(() => expect(within(screen.getByRole('tabpanel')).getByText('Signature is valid')).toBeInTheDocument());
        expect(PGP_EXAMPLES).toHaveLength(3);
    });

    it('keeps the links of the other tabs apart', () => {
        expect(parsePgpShare('#fmt=cose&m=a')).toBeNull();
        expect(pgpShareFragment({ signature: '', publicKey: ' ', message: '', messageFormat: MessageFormat.Text })).toBe('');
    });
});
