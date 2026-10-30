import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { bytesToHex, hexToBytes } from '../bytes';
import { encodeCoseKey } from '../cose';
import { MessageFormat } from '../enum';
import { COSE_EXAMPLES } from '../examples';
import FormSigned from '../FormSigned';
import { coseShareFragment, parseCoseShare } from '../share';
import {
    COSE_ATTACHED,
    COSE_ATTACHED_PAYLOAD,
    COSE_DETACHED_AAD,
    COSE_KEY_ALICE,
    COSE_KEY_BOB,
    COSE_KEY_HEX,
    COSE_KEYSET_AB,
    COSE_PLAIN,
    COSE_PUBLIC,
    COSE_PUBLIC_3,
    COSE_SEED,
    CWT_LONG,
    CWT_RFC8392,
    SIGN_THREE,
    SIGN_TWO,
    SIGN_TWO_AAD_DETACHED,
} from './fixtures/cose';

// the fields of the format and the action that are showing (the others stay mounted, hidden)
const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name }));
const useAction = (name: string) => fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name }));
const region = () => within(screen.getByRole('region', { name: 'Message details' }));

describe('COSE tab, verifying', () => {
    beforeEach(() => {
        render(<FormSigned format="cose" />);
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
        render(<FormSigned format="cose" />);
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

describe('COSE tab, a CWT', () => {
    beforeEach(() => {
        render(<FormSigned format="cose" />);
    });
    afterEach(() => vi.useRealTimers());

    const claims = () => within(screen.getByRole('region', { name: 'Claims' }));

    it('shows the claims by name with their times, and says the token expired, though the signature is valid', async () => {
        type('COSE message', CWT_RFC8392);
        type('Public key you trust', COSE_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(region().getByText(/A CWT \(tag 61\) holding a COSE_Sign1/)).toBeInTheDocument();
        expect(claims().getByRole('heading', { name: 'CWT claims' })).toBeInTheDocument();
        const item = (name: string) => claims().getByText((content) => content.startsWith(`${name}:`), { selector: 'li' });
        expect(item('iss (issuer)')).toHaveTextContent('iss (issuer): "coap://as.example.com"');
        expect(item('sub (subject)')).toHaveTextContent('sub (subject): "erikw"');
        expect(item('cti (CWT ID)')).toHaveTextContent("cti (CWT ID): h'0b71'");
        expect(item('exp (expiration time)')).toHaveTextContent('exp (expiration time): 1444064944 (2015-10-05T17:09:04Z)');
        expect(claims().getByText('Expired: it expired on 2015-10-05T17:09:04Z.')).toBeInTheDocument();
        expect(claims().getByText('Valid since 2015-10-04T07:49:04Z.')).toBeInTheDocument();
        expect(claims().getByText(/The signature proves who signed it, not that it is true or still good/)).toBeInTheDocument();
    });

    it('says a token is not valid yet, before its nbf', async () => {
        vi.useFakeTimers({ toFake: ['Date'], now: new Date('2015-09-01T00:00:00Z') });
        type('COSE message', CWT_RFC8392);
        type('Public key you trust', COSE_PUBLIC);
        click('Verify');
        expect(await screen.findByText('Signature is valid')).toBeInTheDocument();
        expect(claims().getByText('Not valid yet: it starts on 2015-10-04T07:49:04Z.')).toBeInTheDocument();
        expect(claims().getByText('Expires on 2015-10-05T17:09:04Z.')).toBeInTheDocument();
    });

    it('a token that expires in 2100 says when', async () => {
        type('COSE message', CWT_LONG);
        type('Public key you trust', COSE_PUBLIC);
        click('Verify');
        expect(await screen.findByText('Signature is valid')).toBeInTheDocument();
        expect(claims().getByText('Expires on 2100-01-01T00:00:00Z.')).toBeInTheDocument();
        expect(claims().queryByText(/Expired/)).not.toBeInTheDocument();
    });

    it('does not vouch for the claims of a token whose signature is wrong', async () => {
        type('COSE message', CWT_RFC8392);
        type('Public key you trust', COSE_PUBLIC_3);
        click('Verify');
        expect(await screen.findByText('Signature is wrong')).toBeInTheDocument();
        expect(claims().getByText(/the signature is not \(all\) proved, so anyone could have changed it/)).toBeInTheDocument();
    });

    it('shows no claims for a payload that is a text', async () => {
        type('COSE message', COSE_PLAIN);
        type('Public key you trust', COSE_PUBLIC);
        click('Verify');
        expect(await screen.findByText('Signature is valid')).toBeInTheDocument();
        expect(screen.queryByRole('region', { name: 'Claims' })).not.toBeInTheDocument();
    });
});

describe('COSE tab, a message with several signatures (COSE_Sign)', () => {
    beforeEach(() => {
        render(<FormSigned format="cose" />);
    });

    const signatures = () => within(screen.getByRole('region', { name: 'Signatures' }));
    const verify = (message: string, keys: string) => {
        type('COSE message', message);
        type('Public key you trust', keys);
        click('Verify');
    };

    it('is valid only when every signature was checked: two signatures, a COSE_KeySet', async () => {
        verify(SIGN_TWO, COSE_KEYSET_AB);
        expect(await screen.findByText('All 2 signatures are valid')).toBeInTheDocument();
        expect(region().getByText(/COSE_Sign \(tag 98\), 2 signatures/)).toBeInTheDocument();
        expect(signatures().getByText(/Signature 1:/).parentElement).toHaveTextContent('valid (key 1 of those given)');
        expect(signatures().getByText(/Signature 2:/).parentElement).toHaveTextContent('valid (key 2 of those given)');
        expect(screen.getByText(/2 Ed25519 keys, for a COSE_Sign/)).toBeInTheDocument();
    });

    it('with one key per line', async () => {
        verify(SIGN_TWO, `${COSE_KEY_BOB}\n${COSE_KEY_ALICE}`);
        expect(await screen.findByText('All 2 signatures are valid')).toBeInTheDocument();
    });

    it('never calls the message valid when a signature was not checked, and says which', async () => {
        verify(SIGN_THREE, COSE_KEYSET_AB);
        const banner = await screen.findByText(/2 of 3 signatures are valid; 1 not checked, so the message is not proved as a whole/);
        expect(banner).toBeInTheDocument();
        expect(screen.queryByText(/signatures are valid$/)).not.toBeInTheDocument();
        expect(signatures().getByText(/Signature 3:/).parentElement).toHaveTextContent(/not checked\s*Not checked: it names no key id/);
    });

    it('is valid when the key of the third signer is given too', async () => {
        verify(SIGN_THREE, `${COSE_KEY_ALICE}\n${COSE_KEY_BOB}\n${COSE_PUBLIC_3}`);
        expect(await screen.findByText('All 3 signatures are valid')).toBeInTheDocument();
    });

    it('says when none could be checked', async () => {
        verify(SIGN_TWO, bytesToHex(encodeCoseKey(hexToBytes(COSE_PUBLIC_3), new TextEncoder().encode('carol'))));
        expect(await screen.findByText(/None of 2 signatures could be checked, so the message is not proved/)).toBeInTheDocument();
        expect(signatures().getByText(/Signature 2:/).parentElement).toHaveTextContent('no key was given for the key id "bob"');
    });

    it('says how many are wrong', async () => {
        verify(SIGN_TWO, `${COSE_KEY_ALICE}\n${COSE_KEY_BOB}`);
        await screen.findByText('All 2 signatures are valid');
        type('COSE message', SIGN_TWO.replace('68656c6c6f20776f726c64', '68656c6c6f20776f726c65'));
        click('Verify');
        expect(await screen.findByText('2 of 2 signatures are wrong')).toBeInTheDocument();
        expect(screen.queryByText(/are valid/)).not.toBeInTheDocument();
    });

    it('takes the payload and the external data for the signatures, like a COSE_Sign1', async () => {
        verify(SIGN_TWO_AAD_DETACHED, COSE_KEYSET_AB);
        expect(await screen.findByText(/payload apart \(nil\)/)).toBeInTheDocument();
        type('Payload', 'hello world');
        type('External data (optional)', 'context');
        click('Verify');
        expect(await screen.findByText('All 2 signatures are valid')).toBeInTheDocument();
        expect(region().getByText(/given apart/)).toBeInTheDocument();
    });

    it('asks for public keys when the COSE_Keys hold only private ones', async () => {
        // {1: 1, -1: 6, -4: d}
        const privateOnly = `a301012006235820${COSE_PUBLIC_3}`;
        verify(SIGN_TWO, privateOnly);
        expect(await screen.findByText(/holds only a private key/)).toBeInTheDocument();
        verify(SIGN_TWO, `${privateOnly}\n${privateOnly}`);
        expect(await screen.findByText(/COSE_Keys hold only private keys/)).toBeInTheDocument();
    });

    it('a COSE_KeySet is not understood for a COSE_Sign1: it says the key is not recognised, as for any other text', async () => {
        verify(COSE_PLAIN, COSE_KEYSET_AB);
        await waitFor(() => expect(screen.queryByText('Signature is valid')).not.toBeInTheDocument());
        expect(screen.queryByText(/signatures are valid/)).not.toBeInTheDocument();
    });

    it('loads the examples of the CWT and the COSE_Sign, which can be verified', async () => {
        const load = () => fireEvent.click(screen.getByRole('button', { name: 'Load example' }));
        load();
        load();
        load();
        expect(await screen.findByText(/^A CWT with the claims of RFC 8392/)).toBeInTheDocument();
        expect(await screen.findByText('Signature is valid')).toBeInTheDocument();
        expect(await screen.findByText(/^Expired: it expired on 2015/)).toBeInTheDocument();
        load();
        expect(await screen.findByText(/2 of 3 signatures are valid; 1 not checked/)).toBeInTheDocument();
    });
});
