import { MessageFormat } from '../enum';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import FormSign from '../FormSign';
import FormVerify from '../FormVerify';
import { MAX_FILE_BYTES } from '../messagefile';
import VerifyEd25519, { generateKeyPair } from '../signature';
import { setFormats } from './helpers';

const binary = new Uint8Array([0, 1, 2, 0xff, 0xfe, 0x80]); // not valid UTF-8: only a file can carry it

const choose = (file: File) => {
    const input = screen.getByLabelText('Message file') as HTMLInputElement;
    fireEvent.change(input, { target: { files: [file] } });
};

describe('Message from a file', () => {
    beforeEach(() => {
        setFormats('hex');
    });

    it('signs the bytes of the file, then verifies them from a file', async () => {
        const pair = await generateKeyPair('hex');
        const { unmount } = render(<FormSign privateKey={pair.privateKey} />);
        choose(new File([binary], 'data.bin'));
        expect(await screen.findByText('data.bin · 6 bytes')).toBeInTheDocument();
        fireEvent.click(screen.getByText('Sign'));
        const signature = (await screen.findByText('Signature:')).parentElement?.parentElement?.querySelector('.result')?.textContent ?? '';
        expect(signature).toMatch(/^[0-9a-f]{128}$/);
        // the same bytes sent as hex verify against that signature
        expect(await new VerifyEd25519('0001 02ff fe80', signature, pair.publicKey, null, MessageFormat.Hex).check()).toBe(true);
        unmount();

        render(<FormVerify publicKey={pair.publicKey} signature={signature} />);
        choose(new File([binary], 'data.bin'));
        await screen.findByText('data.bin · 6 bytes');
        fireEvent.click(screen.getByText('Verify'));
        expect(await screen.findByText('Signature is valid')).toBeInTheDocument();
    });

    it('refuses a file over the limit with a clear message', async () => {
        render(<FormVerify />);
        const big = new File([], 'big.iso');
        Object.defineProperty(big, 'size', { value: MAX_FILE_BYTES + 1 });
        choose(big);
        expect(await screen.findByText(/big\.iso is .* MB: the limit is 100 MB/)).toBeInTheDocument();
        expect(screen.queryByText(/big\.iso ·/)).not.toBeInTheDocument();
    });

    it('goes back to typing, and does not put a file in a share link', async () => {
        render(<FormVerify publicKey="aa" signature="bb" message="typed" />);
        expect(screen.getByLabelText('Copy link to this verification')).toBeEnabled();
        choose(new File([binary], 'data.bin'));
        await screen.findByText('data.bin · 6 bytes');
        expect(screen.getByLabelText('Copy link to this verification')).toBeDisabled();
        expect(screen.getByText(/A link cannot carry a file/)).toBeInTheDocument();

        fireEvent.click(screen.getByText('Type a message'));
        await waitFor(() => expect(screen.queryByText(/data\.bin/)).not.toBeInTheDocument());
        expect((screen.getByLabelText('Message') as HTMLTextAreaElement).value).toBe('typed');
        expect(screen.getByLabelText('Copy link to this verification')).toBeEnabled();
    });
});
