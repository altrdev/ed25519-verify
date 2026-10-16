import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { MessageFormat } from '../enum';
import { COSE_EXAMPLES } from '../examples';
import FormSigned from '../FormSigned';
import { coseShareFragment, parseCoseShare } from '../share';
import { COSE_ATTACHED, COSE_ATTACHED_PAYLOAD, COSE_DETACHED_AAD, COSE_KEY_HEX, COSE_PLAIN, COSE_PUBLIC, COSE_SEED } from './fixtures/cose';

// the fields of the format and the action that are showing (the others stay mounted, hidden)
const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name, exact: true }));
const useFormat = () =>
    fireEvent.click(within(screen.getByRole('group', { name: 'Signature format' })).getByRole('button', { name: 'COSE' }));
const useAction = (name: string) => fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name }));
const region = () => within(screen.getByRole('region', { name: 'Message details' }));

describe('COSE tab, verifying', () => {
    beforeEach(() => {
        render(<FormSigned />);
        useFormat();
    });

    it('verifies the example of the COSE working group and shows both headers, the signed one apart', async () => {
        type('COSE message', COSE_ATTACHED);
        type('Public key you trust', COSE_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(/COSE_Sign1 \(tag 18\), algorithm EdDSA \(-8\)/)).toBeInTheDocument();
        expect(region().getByText(/Protected header/)).toBeInTheDocument();
        expect(region().getByText('alg (1): -8')).toBeInTheDocument();
        expect(region().getByText('content type (3): 0')).toBeInTheDocument();
        expect(region().getByText('kid (4): "11"')).toBeInTheDocument();
        expect(region().getByText(/not signed: anyone could have changed it/)).toBeInTheDocument();
        expect(region().getByText(COSE_ATTACHED_PAYLOAD)).toBeInTheDocument();
    });

    it('takes the message as base64 and the key as a COSE_Key', async () => {
        type('COSE message', Buffer.from(COSE_PLAIN, 'hex').toString('base64'));
        type('Public key you trust', COSE_KEY_HEX);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('COSE_Key (Ed25519)')).toBeInTheDocument();
    });

    it('asks for the payload when the message has none, and for the external data it was signed with', async () => {
        type('COSE message', COSE_DETACHED_AAD);
        type('Public key you trust', COSE_PUBLIC);
        click('Verify');
        expect(await screen.findByText(/payload apart \(nil\)/)).toBeInTheDocument();

        type('Payload', 'hello world');
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());

        type('External data (optional)', 'context');
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(/given apart/)).toBeInTheDocument();
    });

    it('hints at a newline that was lost in a payload given apart', async () => {
        type('COSE message', COSE_DETACHED_AAD);
        type('External data (optional)', 'context');
        type('Public key you trust', COSE_PUBLIC);
        type('Payload', 'hello world\n');
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(await screen.findByText('It is valid with the newline at the end of the message removed.')).toBeInTheDocument();
    });

    it('refuses what it cannot check, with the reason, and never calls it wrong', async () => {
        type('Public key you trust', COSE_PUBLIC);
        type('COSE message', `d28443a10126a04161${'5840'}${'00'.repeat(64)}`);
        click('Verify');
        expect(await screen.findByText(/ES256 \(-7\), only EdDSA/)).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
        type('COSE message', '!!');
        click('Verify');
        expect(await screen.findByText(/neither/)).toBeInTheDocument();
    });

    it('refuses a key named differently from the one in the message', async () => {
        type('COSE message', COSE_ATTACHED); // kid "11"
        type('Public key you trust', `a4010120062158${'20'}${COSE_PUBLIC}0242${'3232'}`.replace('a4', 'a4'));
        click('Verify');
        expect(await screen.findByText(/names the key "11", the key you gave is "22"/)).toBeInTheDocument();
    });

    it('goes through the examples', async () => {
        const load = () =>
            fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        load();
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('EdDSA-01 of the COSE working group.')).toBeInTheDocument();
        load();
        await waitFor(() => expect(screen.getByText('A payload that travels apart.')).toBeInTheDocument());
        await waitFor(() => expect(region().getByText(/given apart/)).toBeInTheDocument());
    });

    it('copies a link with the message, the key, the payload and the external data', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        type('COSE message', COSE_DETACHED_AAD);
        type('Payload', 'hello world');
        type('External data (optional)', 'context');
        type('Public key you trust', COSE_PUBLIC);
        fireEvent.click(
            screen.getAllByRole('button', { name: 'Copy link to this verification' }).find((b) => !b.closest('[hidden]')) as HTMLElement,
        );
        await waitFor(() => expect(writeText).toHaveBeenCalled());
        expect(parseCoseShare(new URL(writeText.mock.calls[0][0]).hash)).toMatchObject({
            message: COSE_DETACHED_AAD,
            payload: 'hello world',
            externalData: 'context',
            publicKey: COSE_PUBLIC,
        });
    });
});

describe('COSE tab, creating', () => {
    beforeEach(() => {
        render(<FormSigned />);
        useFormat();
        useAction('Create a signature');
    });

    it('gives byte for byte the example of the COSE working group', async () => {
        type('Private key', COSE_SEED);
        type('Payload', COSE_ATTACHED_PAYLOAD);
        type('Key ID (optional)', '11');
        type('Content type (optional)', '0');
        click('Sign');
        await screen.findByText((_, element) => element?.className === 'result' && element.textContent === COSE_ATTACHED);
        expect(field('Public key to verify it (COSE_Key)').value).toMatch(/^a40101200621582/);
    });

    it('writes the message in base64, apart from its payload, and without the tag', async () => {
        type('Private key', COSE_SEED);
        type('Payload', 'hello world');
        fireEvent.click(screen.getByRole('button', { name: 'Apart (nil)' }));
        fireEvent.click(screen.getByRole('button', { name: 'No tag' }));
        click('Sign');
        await screen.findByText((_, element) => element?.className === 'result' && /^[0-9a-f]+$/.test(element.textContent ?? ''));
        fireEvent.click(within(screen.getByRole('group', { name: 'Show the message as' })).getByRole('button', { name: 'Base64' }));
        const bytes = Buffer.from(COSE_PLAIN, 'hex');
        expect(bytes.length).toBeGreaterThan(0);
        await screen.findByText((_, element) => element?.className === 'result' && element.textContent?.startsWith('hEOhASeg9') === true);
    });

    it('refuses a content type that is neither a number nor a media type', async () => {
        type('Private key', COSE_SEED);
        type('Payload', 'x');
        type('Content type (optional)', 'json');
        click('Sign');
        expect(await screen.findByText(/number .* or a media type/)).toBeInTheDocument();
    });

    it('reproduces the examples, and says so', async () => {
        const load = () =>
            fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        load();
        click('Sign');
        expect(await screen.findByText('Identical to the message of the example.')).toBeInTheDocument();
        load();
        click('Sign');
        expect(await screen.findByText('Identical to the message of the example.')).toBeInTheDocument();
        type('Payload', 'another payload');
        click('Sign');
        await waitFor(() => expect(screen.queryByText('Identical to the message of the example.')).not.toBeInTheDocument());
    });
});

describe('a link to a COSE verification', () => {
    afterEach(() => history.replaceState(null, '', '/'));

    it('opens the signed formats tab on COSE, filled in and verified', async () => {
        history.replaceState(
            null,
            '',
            `/${coseShareFragment({ message: COSE_ATTACHED, publicKey: COSE_PUBLIC, payload: '', payloadFormat: MessageFormat.Text, externalData: '' })}`,
        );
        render(<App />);
        await waitFor(() => expect(within(screen.getByRole('tabpanel')).getByText('Signature is valid')).toBeInTheDocument());
        expect(COSE_EXAMPLES).toHaveLength(2);
    });

    it('keeps the links of the other tabs apart', () => {
        expect(parseCoseShare('#fmt=minisign&sig=a')).toBeNull();
        expect(coseShareFragment({ message: '', publicKey: ' ', payload: '', payloadFormat: MessageFormat.Text, externalData: 'x' })).toBe(
            '',
        );
    });
});
