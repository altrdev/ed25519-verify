import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '../bytes';
import { EXAMPLES, SIGNABLE_EXAMPLES } from '../examples';
import FormSign from '../FormSign';
import FormVerify from '../FormVerify';
import VerifyEd25519 from '../signature';
import { setFormats } from './helpers';

describe('examples', () => {
    it.each(EXAMPLES.map((example) => [example.title, example] as const))('%s gives the verdict it says', async (_title, example) => {
        const verifier = new VerifyEd25519(example.message, example.signature, example.publicKey, null, example.messageFormat);
        expect(await verifier.verdict()).toBe(example.verdict);
    });

    it.each(SIGNABLE_EXAMPLES.map((example) => [example.title, example] as const))(
        '%s: the private key gives the public key and the published signature',
        async (_title, example) => {
            const seed = hexToBytes(example.privateKey as string);
            expect(bytesToHex(await ed25519PublicKey(seed))).toBe(example.publicKey);
            const message = hexToBytes(example.message);
            expect(bytesToHex(await ed.signAsync(message, seed))).toBe(example.signature);
        },
    );

    it('has the three RFC 8032 vectors and a ZIP215 one, each with a source', () => {
        expect(EXAMPLES.map((example) => example.verdict)).toEqual(['valid', 'valid', 'valid', 'permissive-only']);
        for (const example of EXAMPLES) expect(example.source).toMatch(/^https:\/\//);
    });
});

const ed25519PublicKey = (seed: Uint8Array) => ed.getPublicKeyAsync(seed);

describe('Load example on the Verify tab', () => {
    beforeEach(() => setFormats('hex'));

    it('fills the form and shows the answer, going through every example and round again', async () => {
        render(<FormVerify />);
        const load = () => fireEvent.click(screen.getByRole('button', { name: 'Load example' }));

        load();
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.getByLabelText('Public key', { selector: 'textarea' })).toHaveValue(EXAMPLES[0].publicKey);
        expect(screen.getByText('RFC 8032 test 1.')).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Source' })).toHaveAttribute('href', EXAMPLES[0].source);

        load();
        await waitFor(() => expect(screen.getByText('RFC 8032 test 2.')).toBeInTheDocument());
        await waitFor(() => expect(screen.getByLabelText('Public key', { selector: 'textarea' })).toHaveValue(EXAMPLES[1].publicKey));
        expect(screen.getByText('Signature is valid')).toBeInTheDocument();

        load();
        await waitFor(() => expect(screen.getByText('RFC 8032 test 3.')).toBeInTheDocument());
        load();
        await waitFor(() => expect(screen.getByText(/not valid under the strict RFC 8032 rules/)).toBeInTheDocument());
        expect(screen.getByText('Only valid under ZIP215.')).toBeInTheDocument();

        load(); // round again
        await waitFor(() => expect(screen.getByText('RFC 8032 test 1.')).toBeInTheDocument());
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
    });

    it('replaces what was typed, including an earlier error', async () => {
        render(<FormVerify publicKey="abcd" message="typed" signature="12" />);
        fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
        expect(await screen.findAllByText(/expected/i)).not.toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: 'Load example' }));
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.queryByText(/expected 32 bytes/i)).not.toBeInTheDocument();
    });
});

describe('Load example on the Sign tab', () => {
    beforeEach(() => setFormats('hex'));

    it('loads the private key of a vector, and tells when the signature is the published one', async () => {
        render(<FormSign />);
        fireEvent.click(screen.getByRole('button', { name: 'Load example' }));
        const example = SIGNABLE_EXAMPLES[0];
        expect(screen.getByLabelText('Private key', { selector: 'textarea' })).toHaveValue(example.privateKey);
        await waitFor(() => expect(screen.getByRole('textbox', { name: 'Deduced Public key' })).toHaveValue(example.publicKey));

        fireEvent.click(screen.getByRole('button', { name: 'Sign' }));
        await waitFor(() => expect(screen.getByText(example.signature)).toBeInTheDocument());
        expect(screen.getByText('Identical to the signature published in RFC 8032.')).toBeInTheDocument();

        // another message: a different signature, so no claim
        fireEvent.input(screen.getAllByLabelText('Message', { selector: 'textarea' })[0], { target: { value: 'ff' } });
        fireEvent.click(screen.getByRole('button', { name: 'Sign' }));
        await waitFor(() => expect(screen.queryByText(example.signature)).not.toBeInTheDocument());
        expect(screen.queryByText(/Identical to the signature published/)).not.toBeInTheDocument();
    });
});
