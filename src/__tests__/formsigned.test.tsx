import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import FormSigned from '../FormSigned';

// RFC 8037, appendix A: the key (RFC 8032 test 1) and its token
const D = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';
const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const JWK_PUBLIC = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: X });
const TOKEN =
    'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';

const field = (name: string) => screen.getByLabelText(name, { selector: 'textarea' }) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name, exact: true }));

describe('JWS / JWT tab, verifying', () => {
    it('says a token of RFC 8037 is valid, and shows what it contains', async () => {
        render(<FormSigned />);
        type('Token', TOKEN);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        const contents = screen.getByRole('region', { name: 'Token contents' });
        expect(within(contents).getByText('Example of Ed25519 signing')).toBeInTheDocument();
        expect(within(contents).getByText(/"alg": "EdDSA"/)).toBeInTheDocument();
    });

    it('says a changed token is wrong, and keeps the contents visible (what it says is not what is proven)', async () => {
        render(<FormSigned />);
        const [header, payload, signature] = TOKEN.split('.');
        type('Token', `${header}.${payload.slice(0, -1)}A.${signature}`);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(screen.getByRole('region', { name: 'Token contents' })).toBeInTheDocument();
    });

    it('creates a token, which the other mode verifies, with the times of the JWT noted', async () => {
        render(<FormSigned />);
        fireEvent.click(screen.getByRole('button', { name: 'Create a token' }));
        type('Private key', Buffer.from(D, 'base64url').toString('hex'));
        type('Payload', '{"sub":"ada","exp":1000000000}');
        click('Sign');
        const token = (await screen.findByText(/^eyJ[\w-]+\.[\w-]+\.[\w-]+$/)).textContent as string;
        // the public key it gives is the one of the vector, as a JWK
        expect(JSON.parse(field('Public key to verify it, as a JWK').value)).toMatchObject({ kty: 'OKP', crv: 'Ed25519', x: X });

        fireEvent.click(screen.getByRole('button', { name: 'Verify a token' }));
        type('Token', token);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText('Expired: it expired on 2001-09-09T01:46:40Z.')).toBeInTheDocument();
    });

    it('explains an input that cannot be verified instead of saying the signature is wrong', async () => {
        render(<FormSigned />);
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
        render(<FormSigned />);
        type('Token', TOKEN);
        type('Public key', JWK_PUBLIC);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        type('Token', `${TOKEN}x`);
        expect(screen.queryByText('Signature is valid')).not.toBeInTheDocument();
    });
});
