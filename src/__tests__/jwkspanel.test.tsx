import * as ed from '@noble/ed25519';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import App from '../App';
import { hexToBytes } from '../bytes';
import { JWS_EXAMPLES } from '../examples';
import FormSigned from '../FormSigned';
import { bytesOfInput, signingInputOf, tokenOf } from '../jws';
import { jwsShareFragment } from '../share';

const SEED_1 = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const SEED_2 = '6b775269140d487bed9fd684816ef7d86543b14fbb9a56d033ef0cddc604d3b7';
const X1 = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const X2 = 'HTAZSIhmy0zYZuoxA9tij6796Ai6Sm-_uDVPqvzc5Uw';
const jwk = (x: string, kid?: string) => ({ kty: 'OKP', crv: 'Ed25519', x, ...(kid !== undefined && { kid }) });
const SET = JSON.stringify({ keys: [jwk(X1, 'key-1'), jwk(X2, 'key-2'), { kty: 'RSA', kid: 'r', n: 'AQAB', e: 'AQAB' }] });
const SET_NO_KIDS = JSON.stringify({ keys: [jwk(X1), jwk(X2)] });

async function token(header: object, seed: string, payload = '{"sub":"ada"}') {
    const input = signingInputOf(JSON.stringify(header), payload);
    return tokenOf(input, await ed.signAsync(bytesOfInput(input), hexToBytes(seed)));
}

const field = (name: string) =>
    screen.getAllByLabelText(name, { selector: 'textarea' }).find((element) => !element.closest('[hidden]')) as HTMLTextAreaElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name, exact: true }));

describe('JWS tab with a JWK Set', () => {
    beforeEach(() => {
        render(<FormSigned />);
    });

    it('picks the key the token names, and says which', async () => {
        type('Token', await token({ alg: 'EdDSA', kid: 'key-2' }, SEED_2));
        type('Public key', SET);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(
            screen.getByText(/Using the key "key-2" of the set, as the token asks \(1 other key of another type left out\)/),
        ).toBeInTheDocument();
        // the other key of the set would not have verified it
        type('Token', await token({ alg: 'EdDSA', kid: 'key-1' }, SEED_2));
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
    });

    it('says what the set has when it has no such key, and does not say wrong', async () => {
        type('Token', await token({ alg: 'EdDSA', kid: 'other' }, SEED_2));
        type('Public key', SET);
        click('Verify');
        expect(
            await screen.findByText('The set has no key "other", the one the token names. It has: "key-1", "key-2".'),
        ).toBeInTheDocument();
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
    });

    it('refuses two keys with the same kid', async () => {
        type('Token', await token({ alg: 'EdDSA', kid: 'same' }, SEED_2));
        type('Public key', JSON.stringify({ keys: [jwk(X1, 'same'), jwk(X2, 'same')] }));
        click('Verify');
        expect(await screen.findByText(/Two keys of the set have the kid "same"/)).toBeInTheDocument();
    });

    it('asks which key when the token names none and the set has several; a click settles it', async () => {
        type('Token', await token({ alg: 'EdDSA' }, SEED_2));
        type('Public key', SET_NO_KIDS);
        click('Verify');
        expect(await screen.findByText(/names no key \(no "kid"\) and the set has 2 Ed25519 keys: pick/)).toBeInTheDocument();
        expect(screen.queryByText('Signature is valid')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Use the key number 2' }));
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText(/Using the key number 2 of the set, the one you picked/)).toBeInTheDocument();
        // editing the set drops the pick
        type('Public key', SET_NO_KIDS.replace(' ', ''));
        expect(screen.queryByText(/the one you picked/)).not.toBeInTheDocument();
    });

    it('uses the only key of a set when the token names none', async () => {
        type('Token', await token({ alg: 'EdDSA' }, SEED_1));
        type('Public key', JSON.stringify({ keys: [jwk(X1)] }));
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText(/names no key and the set has one Ed25519 key: using it/)).toBeInTheDocument();
    });

    it('explains a set without an Ed25519 key, and a malformed one', async () => {
        type('Token', await token({ alg: 'EdDSA', kid: 'a' }, SEED_1));
        type('Public key', JSON.stringify({ keys: [{ kty: 'RSA' }] }));
        click('Verify');
        expect(await screen.findByText('The set has no Ed25519 key (its 1 key is of another type).')).toBeInTheDocument();
        type('Public key', JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }] }));
        click('Verify');
        expect(await screen.findByText(/"x" is not 32 bytes/)).toBeInTheDocument();
    });

    it('never takes a key from the token: a jwk in its header is ignored, and the set decides', async () => {
        // the token carries its own key (the one that signed it) and names none in the set
        const forged = await token({ alg: 'EdDSA', kid: 'key-1', jwk: jwk(X2) }, SEED_2);
        type('Token', forged);
        type('Public key', SET);
        click('Verify');
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument()); // key-1 of the set did not sign it
        expect(screen.getByText(/Using the key "key-1" of the set/)).toBeInTheDocument();
    });

    it('goes through the examples: the set one verifies, and Create reproduces its token', async () => {
        const load = () =>
            fireEvent.click(screen.getAllByRole('button', { name: 'Load example' }).find((b) => !b.closest('[hidden]')) as HTMLElement);
        load();
        load();
        load();
        await waitFor(() => expect(screen.getByText('A token and the key set of its issuer.')).toBeInTheDocument());
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByText(/Using the key "key-2" of the set/)).toBeInTheDocument();
        expect(JWS_EXAMPLES[2].publicKey).toContain('"keys"');

        // the Create tab reproduces the token of the example byte for byte
        fireEvent.click(within(screen.getByRole('group', { name: 'Action' })).getByRole('button', { name: 'Create a signature' }));
        for (let i = 0; i < 3; i++) load();
        click('Sign');
        expect(await screen.findByText('Identical to the token of the example.')).toBeInTheDocument();
    });
});

describe('a link to a token with a key set', () => {
    afterEach(() => history.replaceState(null, '', '/'));

    it('opens the signed formats tab and verifies with the key of the set', async () => {
        history.replaceState(
            null,
            '',
            `/${jwsShareFragment({ token: await token({ alg: 'EdDSA', kid: 'key-2' }, SEED_2), publicKey: SET })}`,
        );
        render(<App />);
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
    });
});
