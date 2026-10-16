import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes, parseBase64 } from '../bytes';
import { diagnose } from '../diagnose';
import { MessageFormat } from '../enum';
import FormVerify from '../FormVerify';
import VerifyEd25519 from '../signature';
import { PUBLIC_HEX, SEED_HEX } from './fixtures/keys';

const seed = hexToBytes(SEED_HEX);
const publicKey = hexToBytes(PUBLIC_HEX);
const utf8 = (text: string) => new TextEncoder().encode(text);
const sign = (message: Uint8Array) => ed.signAsync(message, seed);

/** The hints for `typed` (a message as typed, in `format`) when the signature belongs to `signed`. */
async function hintsFor(typed: string, signed: Uint8Array, format = MessageFormat.Text, key = publicKey) {
    const signature = await sign(signed);
    const ed25519 = new VerifyEd25519(typed, bytesToHex(signature), bytesToHex(key), null, format);
    expect(await ed25519.verdict()).toBe('invalid');
    return ed25519.hints();
}

describe('hints for a wrong signature', () => {
    it('finds a newline that was added or lost', async () => {
        expect((await hintsFor('hello', utf8('hello\n'))).fixes).toEqual(['It is valid with a newline added at the end of the message.']);
        expect((await hintsFor('hello\n', utf8('hello'))).fixes).toEqual([
            'It is valid with the newline at the end of the message removed.',
        ]);
        expect((await hintsFor('hello\r\n', utf8('hello'))).fixes).toContain(
            'It is valid with the newline at the end of the message removed.',
        );
    });

    it('finds trailing spaces, line breaks written the other way, and Unicode normalisation', async () => {
        expect((await hintsFor('hello  \n\n', utf8('hello'))).fixes).toEqual([
            'It is valid with the spaces and line breaks at the end of the message removed.',
        ]);
        expect((await hintsFor('a\r\nb', utf8('a\nb'))).fixes).toEqual([
            'It is valid with the line breaks written as \\n instead of \\r\\n.',
        ]);
        expect((await hintsFor('a\nb', utf8('a\r\nb'))).fixes).toEqual(['It is valid with the line breaks written as \\r\\n.']);
        expect((await hintsFor('café', utf8('café'))).fixes).toEqual([
            'It is valid with the message normalised as Unicode NFD (decomposed accents).',
        ]);
    });

    it('finds a message read in the wrong format', async () => {
        expect((await hintsFor('68656c6c6f', utf8('hello'))).fixes).toEqual([
            'It is valid with the message read as hex (the selector is on Text).',
        ]);
        expect((await hintsFor('aGVsbG8=', utf8('hello'))).fixes).toEqual([
            'It is valid with the message read as base64 (the selector is on Text).',
        ]);
        expect((await hintsFor('68656c6c6f', utf8('68656c6c6f'), MessageFormat.Hex)).fixes).toEqual([
            'It is valid with the message read as text (the selector is on Hex).',
        ]);
        // "deadbeef" typed with the selector on Hex, but the signed message was that text as base64 (6 bytes)
        const base64Bytes = parseBase64('deadbeef') as Uint8Array;
        expect((await hintsFor('deadbeef', base64Bytes, MessageFormat.Hex)).fixes).toEqual([
            'It is valid with the message read as base64 instead.',
        ]);
    });

    it('finds a hash that was signed instead of the message', async () => {
        const sha256 = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8('hello')));
        const sha512 = new Uint8Array(await crypto.subtle.digest('SHA-512', utf8('hello')));
        expect((await hintsFor('hello', sha256)).fixes).toEqual([
            'It is valid with the SHA-256 hash of the message signed instead of the message (the raw bytes of the hash).',
        ]);
        expect((await hintsFor('hello', utf8(bytesToHex(sha512)))).fixes).toEqual([
            'It is valid with the SHA-512 hash of the message signed instead of the message (the hash written as hex text).',
        ]);
    });

    it('notices a private key in the public key field', async () => {
        const { fixes } = await hintsFor('hello', utf8('hello'), MessageFormat.Text, seed);
        expect(fixes).toEqual([
            `The field "Public key" holds a private key (a seed): the signature is valid for its public key, ${PUBLIC_HEX}. Use that one.`,
        ]);
    });

    it('notices the halves of the signature in the other order', async () => {
        const signature = await sign(utf8('hello'));
        const swapped = new Uint8Array([...signature.slice(32), ...signature.slice(0, 32)]);
        const ed25519 = new VerifyEd25519('hello', bytesToHex(swapped), PUBLIC_HEX, null);
        expect(await ed25519.verdict()).toBe('invalid');
        expect((await ed25519.hints()).fixes).toEqual(['It is valid with the two halves of the signature (R and S) swapped.']);
    });

    it('says nothing for a signature that is simply wrong', async () => {
        const hints = await hintsFor('hello', utf8('something else entirely'));
        expect(hints.fixes).toEqual([]);
        expect(hints.facts).toEqual([]);
    });

    it('states the facts about a signature that cannot be valid', async () => {
        const L = (1n << 252n) + 27742317777372353535851937790883648493n;
        const signature = await sign(utf8('hello'));
        // S + L is the same number modulo the group order, but is not reduced
        const s = signature.slice(32).reduceRight((total, byte) => (total << 8n) | BigInt(byte), 0n) + L;
        const bytes = Uint8Array.from({ length: 32 }, (_, i) => Number((s >> BigInt(8 * i)) & 0xffn));
        const nonCanonical = new Uint8Array([...signature.slice(0, 32), ...bytes]);
        const found = await diagnose(
            { publicKey, signature: nonCanonical, message: 'hello', messageFormat: MessageFormat.Text },
            utf8('hello'),
        );
        expect(found.facts).toHaveLength(1);
        expect(found.facts[0]).toMatch(/not reduced/);

        // a y coordinate that is not on the curve
        let offCurve: Uint8Array | undefined;
        for (let y = 2; !offCurve; y++) {
            const candidate = new Uint8Array(32);
            candidate[0] = y;
            try {
                ed.Point.fromBytes(candidate, false);
            } catch {
                offCurve = candidate;
            }
        }
        const badR = new Uint8Array([...offCurve, ...signature.slice(32)]);
        expect(
            (await diagnose({ publicKey, signature: badR, message: 'hello', messageFormat: MessageFormat.Text }, utf8('hello'))).facts[0],
        ).toMatch(/\(R\) is not a point/);
        expect(
            (await diagnose({ publicKey: offCurve, signature, message: 'hello', messageFormat: MessageFormat.Text }, utf8('hello')))
                .facts[0],
        ).toMatch(/public key is not a point/);
        const identity = new Uint8Array(32);
        identity[0] = 1;
        expect(
            (await diagnose({ publicKey: identity, signature, message: 'hello', messageFormat: MessageFormat.Text }, utf8('hello')))
                .facts[0],
        ).toMatch(/small order/);
    });
});

describe('hints in the form', () => {
    it('shows them under the banner, and only for a wrong signature', async () => {
        const signature = bytesToHex(await sign(utf8('hello\n')));
        render(<FormVerify publicKey={PUBLIC_HEX} message="hello" signature={signature} />);
        fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(await screen.findByText('It is valid with a newline added at the end of the message.')).toBeInTheDocument();
        expect(screen.getByRole('heading', { name: 'The signature is valid if you change something' })).toBeInTheDocument();

        // editing the message hides them with the verdict
        fireEvent.input(screen.getAllByLabelText('Message', { selector: 'textarea' })[0], { target: { value: 'hello\n' } });
        expect(screen.queryByText('Signature is wrong')).not.toBeInTheDocument();
        expect(screen.queryByText(/It is valid with/)).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
        await waitFor(() => expect(screen.getByText('Signature is valid')).toBeInTheDocument());
        expect(screen.queryByRole('region', { name: 'Why it may be wrong' })).not.toBeInTheDocument();
    });

    it('shows nothing extra for a signature that is simply wrong', async () => {
        const signature = bytesToHex(await sign(utf8('another message')));
        render(<FormVerify publicKey={PUBLIC_HEX} message="hello" signature={signature} />);
        fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
        await waitFor(() => expect(screen.getByText('Signature is wrong')).toBeInTheDocument());
        expect(screen.queryByRole('region', { name: 'Why it may be wrong' })).not.toBeInTheDocument();
    });
});
