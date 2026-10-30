import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { MessageFormat } from '../enum';
import { PGP_EXAMPLES } from '../examples';
import FormSigned from '../FormSigned';
import { parsePgpShare, pgpShareFragment } from '../share';
import { bytesToHex } from '../bytes';
import { candidateKeys, parseCertificate, parsePgpSignature, readPgp } from '../openpgp';
import {
    PGP_CLEARSIGNED,
    PGP_EXPIRED_PUBLIC,
    PGP_EXPIRED_SIG,
    PGP_PARTS_REVOKED_PUBLIC,
    PGP_PARTS_REVOKED_SIG,
    PGP_REVOKED_PUBLIC,
    PGP_REVOKED_SIG,
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
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name }));
const useAction = (name: string) => fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name }));
const region = () => within(screen.getByRole('region', { name: 'Signature details' }));
const spaced = (fingerprint: string) => fingerprint.replace(/(.{4})(?=.)/g, '$1 ');

describe('OpenPGP tab, verifying', () => {
    beforeEach(() => {
        render(<FormSigned format="pgp" />);
    });

    it('verifies a signature made by gpg with the key block, finds the subkey that made it, and says what it holds', async () => {
        type('Signature', PGP_DETACHED_SUB);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(new RegExp(`Key: ${spaced(PGP_SUBKEY_FINGERPRINT)} \\(a subkey, version 4\\)`))).toBeInTheDocument();
        expect(region().getByText('User ID Fixture <fixture@example.com>: signed by the key itself (checked)')).toBeInTheDocument();
        expect(region().getByText('The subkey does not expire.')).toBeInTheDocument();
        expect(screen.queryByText(/But read it with this/)).not.toBeInTheDocument();
        expect(region().getByText(/it is the message that was signed/)).toBeInTheDocument();
        expect(region().getByText(/EdDSA \(algorithm 22\), hash SHA-512/)).toBeInTheDocument();
        expect(region().getByText(/looks only inside the key block you pasted/)).toBeInTheDocument();
        expect(region().getByText(/does not know whether anyone certified the key/)).toBeInTheDocument();
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

    it('a valid signature of a key that has expired says so in the verdict, with the date and the order', async () => {
        type('Signature', PGP_EXPIRED_SIG);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_EXPIRED_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText(/But read it with this, from the key block/)).toBeInTheDocument();
        // in the verdict only: the details do not repeat it
        expect(
            screen.getByText('The subkey expired on 2020-06-29. The signature was made before that, on 2020-03-01.'),
        ).toBeInTheDocument();
        expect(
            screen.getByText('The primary key expired on 2020-12-31. The signature was made before that, on 2020-03-01.'),
        ).toBeInTheDocument();
    });

    it('a revoked key: the reason, and that the revocation is in the block', async () => {
        type('Signature', PGP_REVOKED_SIG);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_REVOKED_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(
            screen.getByText(/The primary key was revoked on 2020-06-01 \(the key was compromised: "fixture compromised"\)/),
        ).toBeInTheDocument();
    });

    it('lists each user ID with what was found, a revoked one included, and the subkey revocation after the signature', async () => {
        type('Signature', PGP_PARTS_REVOKED_SIG);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', PGP_PARTS_REVOKED_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText('User ID Kept Fixture <kept@example.com>: signed by the key itself (checked)')).toBeInTheDocument();
        expect(
            region().getByText(
                'User ID Dropped Fixture <dropped@example.com>: signed by the key itself (checked); revoked on 2020-06-01 (the user ID is no longer in use)',
            ),
        ).toBeInTheDocument();
        expect(
            screen.getByText(/The subkey was revoked on 2020-06-01.*The signature was made before the revocation\./),
        ).toBeInTheDocument();
    });

    it('a plain key has no block to look into, and the page says it did not look', async () => {
        const certificate = await parseCertificate((readPgp(PGP_V6_PUBLIC) as { armored: { bytes: Uint8Array } }).armored.bytes);
        const signature = parsePgpSignature((readPgp(PGP_V6_SIG) as { armored: { bytes: Uint8Array } }).armored.bytes);
        type('Signature', PGP_V6_SIG);
        type('Message', PGP_MESSAGE);
        type('Public key you trust', bytesToHex(candidateKeys(signature, certificate.keys)[0].publicKey));
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(/A plain key carries nothing to look at/)).toBeInTheDocument();
        expect(screen.queryByText(/But read it with this/)).not.toBeInTheDocument();
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
