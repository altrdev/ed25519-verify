import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import FormSigned from '../FormSigned';
import { jwsShareFragment, parseJwsShare, parseShareFragment } from '../share';

// RFC 8037, appendix A: the key (RFC 8032 test 1) and its token
const D = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';
const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const JWK_PUBLIC = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: X });
const TOKEN =
    'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';

// the fields of the format and the action that are showing (the others stay mounted, hidden)
const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name, exact: true }));

describe('JWS / JWT tab, verifying', () => {
    it('says a token of RFC 8037 is valid, and shows what it contains', async () => {
        render(<FormSigned format="jws" />);
        type('Token', TOKEN);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        const contents = screen.getByRole('region', { name: 'Token contents' });
        expect(within(contents).getByText('Example of Ed25519 signing')).toBeInTheDocument();
        expect(within(contents).getByText(/"alg": "EdDSA"/)).toBeInTheDocument();
    });

    it('says a changed token is wrong, and keeps the contents visible (what it says is not what is proven)', async () => {
        render(<FormSigned format="jws" />);
        const [header, payload, signature] = TOKEN.split('.');
        type('Token', `${header}.${payload.slice(0, -1)}A.${signature}`);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(screen.getByRole('region', { name: 'Token contents' })).toBeInTheDocument();
    });

    it('creates a token, which the other mode verifies, with the times of the JWT noted', async () => {
        render(<FormSigned format="jws" />);
        fireEvent.click(screen.getByRole('button', { name: 'Create a signature' }));
        type('Private key', Buffer.from(D, 'base64url').toString('hex'));
        type('Payload', '{"sub":"ada","exp":1000000000}');
        click('Sign');
        const token = (await screen.findByText(/^eyJ[\w-]+\.[\w-]+\.[\w-]+$/)).textContent as string;
        // the public key it gives is the one of the vector, as a JWK
        expect(JSON.parse(field('Public key to verify it, as a JWK').value)).toMatchObject({ kty: 'OKP', crv: 'Ed25519', x: X });

        fireEvent.click(screen.getByRole('button', { name: 'Verify a signature' }));
        type('Token', token);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('Expired: it expired on 2001-09-09T01:46:40Z.')).toBeInTheDocument();
    });

    it('explains an input that cannot be verified instead of saying the signature is wrong', async () => {
        render(<FormSigned format="jws" />);
        type('Token', 'eyJhbGciOiJub25lIn0.e30.');
        type('Public key', JWK_PUBLIC);
        click('Verify');
        expect(await screen.findByText(/"none".*not signed at all/)).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();

        type('Token', 'a.b');
        click('Verify');
        expect(await screen.findByText(/three parts/)).toBeInTheDocument();

        type('Token', TOKEN);
        type('Public key', 'nothex');
        click('Verify');
        expect(await screen.findAllByText(/Public key: expected 32 bytes/)).not.toHaveLength(0);
    });

    it('drops the result when something is edited', async () => {
        render(<FormSigned format="jws" />);
        type('Token', TOKEN);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        type('Token', `${TOKEN}x`);
        expect(screen.queryByText('Signature is valid')).not.toBeInTheDocument();
    });
});

describe('JWS tab: the same help as the other tabs', () => {
    const bytesOf = (value: string) => Uint8Array.from(Buffer.from(value, 'base64url'));
    const swapped = () => {
        const [header, payload, signature] = TOKEN.split('.');
        const bytes = bytesOf(signature);
        return `${header}.${payload}.${Buffer.from([...bytes.slice(32), ...bytes.slice(0, 32)]).toString('base64url')}`;
    };

    it('hints that the halves of the signature are swapped, and that the public key field holds a private key', async () => {
        render(<FormSigned format="jws" />);
        type('Token', swapped());
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(await screen.findByText('It is valid with the two halves of the signature (R and S) swapped.')).toBeInTheDocument();

        type('Token', TOKEN);
        type('Public key', Buffer.from(D, 'base64url').toString('hex')); // the private key by mistake
        click('Verify');
        expect(await screen.findByText(/holds a private key \(a seed\)/)).toBeInTheDocument();
    });

    it('says nothing more for a signature that is simply wrong, and does not suggest hashes', async () => {
        render(<FormSigned format="jws" />);
        const [header, payload, signature] = TOKEN.split('.');
        type('Token', `${header}.${payload.slice(0, -1)}A.${signature}`);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(screen.queryByRole('region', { name: 'Why it may be wrong' })).not.toBeInTheDocument();
    });

    it('goes through the examples, and the Create tab reproduces the token of the example', async () => {
        render(<FormSigned format="jws" />);
        fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name: 'Verify a signature' }));
        const load = () => fireEvent.click(screen.getAllByRole('button', { name: 'Load example' })[0]);
        load();
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('RFC 8037 appendix A.4.')).toBeInTheDocument();
        load();
        await waitFor(() => expect(screen.getByText('A JWT that has expired.')).toBeInTheDocument());
        await screen.findByText(/^Expired: it expired on/);

        fireEvent.click(screen.getByRole('button', { name: 'Create a signature' }));
        fireEvent.click(screen.getAllByRole('button', { name: 'Load example' })[0]); // the visible panel's
        click('Sign');
        expect(await screen.findByText('Identical to the token of the example.')).toBeInTheDocument();
        // another payload: no claim
        type('Payload', 'something else');
        click('Sign');
        await waitFor(() => expect(screen.queryByText('Identical to the token of the example.')).not.toBeInTheDocument());
    });

    it('copies a link to the token and the public key, never anything private', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        render(<FormSigned format="jws" />);
        expect(screen.getAllByRole('button', { name: 'Copy link to this verification' })[0]).toBeDisabled();
        type('Token', TOKEN);
        type('Public key', JWK_PUBLIC);
        fireEvent.click(screen.getByRole('button', { name: 'Copy link to this verification' }));
        await waitFor(() => expect(writeText).toHaveBeenCalled());
        const hash = new URL(writeText.mock.calls[0][0]).hash;
        expect(parseJwsShare(hash)).toEqual({ token: TOKEN, publicKey: JWK_PUBLIC });
        expect(hash).not.toContain(D);
    });

    it('opens a token from a text file, and says so for a file that is not text', async () => {
        render(<FormSigned format="jws" />);
        const input = screen.getByLabelText('File for token') as HTMLInputElement;
        fireEvent.change(input, { target: { files: [new File([`${TOKEN}\n`], 'token.jwt')] } });
        await waitFor(() => expect(field('Token').value).toBe(`${TOKEN}\n`));
        fireEvent.change(input, { target: { files: [new File([new Uint8Array(64).fill(0xff)], 'x.bin')] } });
        expect(await screen.findByText('x.bin is not a text file.')).toBeInTheDocument();
    });
});

describe('a link to a token', () => {
    afterEach(() => history.replaceState(null, '', '/'));

    it('opens the tab of the signed formats with the token filled in and the answer shown', async () => {
        history.replaceState(null, '', `/${jwsShareFragment({ token: TOKEN, publicKey: JWK_PUBLIC })}`);
        render(<App />);
        const panel = within(screen.getByRole('tabpanel'));
        expect(panel.getByLabelText('Token', { selector: 'textarea' })).toHaveValue(TOKEN);
        await waitFor(() => expect(panel.getByText('Signature is valid')).toBeInTheDocument());
    });

    it('is not mistaken for the link of the Verify tab, which keeps working', () => {
        expect(parseShareFragment(jwsShareFragment({ token: TOKEN, publicKey: JWK_PUBLIC }))).toBeNull();
        expect(parseJwsShare('#pk=abc&sig=def')).toBeNull();
        expect(jwsShareFragment({ token: ' ', publicKey: '' })).toBe('');
    });
});
