import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { bytesToHex, hexToBytes } from '../bytes';
import { downloadText, FileError, fileNameFor, MAX_FILE_BYTES, readFileForField } from '../files';
import FormSign from '../FormSign';
import FormVerify from '../FormVerify';
import { setFormats } from './helpers';
import { OPENSSH_PUBLIC, PKCS8_PEM, PUBLIC_HEX, SEED_HEX, SPKI_PEM } from './fixtures/keys';

const file = (content: string | Uint8Array, name = 'key') => new File([content as BlobPart], name);

describe('reading a file into a field', () => {
    it('takes the text of a key file as it is', async () => {
        expect(await readFileForField(file(PKCS8_PEM, 'private.pem'), 'key')).toBe(PKCS8_PEM);
        expect(await readFileForField(file(OPENSSH_PUBLIC, 'id_ed25519.pub'), 'key')).toBe(OPENSSH_PUBLIC);
        expect(await readFileForField(file(`${SEED_HEX}\n`), 'key')).toBe(`${SEED_HEX}\n`);
    });

    it('drops a byte order mark', async () => {
        expect(await readFileForField(file(`﻿${PUBLIC_HEX}`), 'key')).toBe(PUBLIC_HEX);
    });

    it('turns a raw binary key or signature into hex', async () => {
        const seed = hexToBytes(SEED_HEX);
        seed[0] = 0xff; // not valid UTF-8
        expect(await readFileForField(file(seed), 'key')).toBe(bytesToHex(seed));
        const keypair = new Uint8Array(64).fill(0xfe);
        expect(await readFileForField(file(keypair), 'key')).toBe(bytesToHex(keypair));
        const signature = new Uint8Array(64).fill(0x90);
        expect(await readFileForField(file(signature), 'signature')).toBe(bytesToHex(signature));
    });

    it('refuses binary data of another size, a key where a signature goes, and a file that is too big', async () => {
        await expect(readFileForField(file(new Uint8Array(31).fill(0xff), 'x.bin'), 'key')).rejects.toThrow(
            /not text, and it is not 32 or 64 bytes/,
        );
        await expect(readFileForField(file(new Uint8Array(32).fill(0xff), 'x.bin'), 'signature')).rejects.toThrow(
            /not 64 bytes of a raw signature/,
        );
        await expect(readFileForField(file(new Uint8Array([0, 1, 2, 3]), 'x.bin'), 'key')).rejects.toThrow(FileError); // a control character is not text
        await expect(readFileForField(file('a'.repeat(MAX_FILE_BYTES + 1), 'big.txt'), 'key')).rejects.toThrow(/too big/);
    });
});

describe('names of the saved files', () => {
    it('are the ones other tools expect', () => {
        expect(fileNameFor('private', 'openssh')).toBe('id_ed25519');
        expect(fileNameFor('public', 'openssh')).toBe('id_ed25519.pub');
        expect(fileNameFor('private', 'pem')).toBe('private.pem');
        expect(fileNameFor('public', 'pem')).toBe('public.pem');
        expect(fileNameFor('private', 'jwk')).toBe('private.jwk');
        expect(fileNameFor('public', 'jwk')).toBe('public.jwk');
        expect(fileNameFor('private', 'solana')).toBe('keypair.json');
        expect(fileNameFor('private', 'hex')).toBe('private-key.txt');
        expect(fileNameFor('public', null)).toBe('public-key.txt');
        expect(fileNameFor('signature', 'base64')).toBe('signature.sig');
    });
});

/** Replaces the browser's download: records the name and the content of what is saved. */
function captureDownloads() {
    const saved: { name: string; text: Promise<string> }[] = [];
    let blob: Blob | undefined;
    URL.createObjectURL = vi.fn((object: Blob | MediaSource) => {
        blob = object as Blob;
        return 'blob:test';
    });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
        const content = blob as Blob;
        saved.push({
            name: this.download,
            text: new Promise((resolve) => {
                const reader = new FileReader();
                reader.onload = () => resolve(reader.result as string);
                reader.readAsText(content);
            }),
        });
    });
    return saved;
}

describe('saving a file', () => {
    afterEach(() => vi.restoreAllMocks());

    it('writes the text with a final line break, under the given name', async () => {
        const saved = captureDownloads();
        downloadText('public.pem', 'abc');
        downloadText('id.pub', 'abc\n');
        expect(saved.map((s) => s.name)).toEqual(['public.pem', 'id.pub']);
        expect(await saved[0].text).toBe('abc\n');
        expect(await saved[1].text).toBe('abc\n');
        expect(document.querySelector('a[download]')).toBeNull(); // the link is not left in the page
    });
});

describe('files in the forms', () => {
    beforeEach(() => setFormats('hex'));
    afterEach(() => vi.restoreAllMocks());

    it('opens a file in the public key field of the Verify tab and reads it like pasted text', async () => {
        render(<FormVerify />);
        const input = screen.getByLabelText('File for public key') as HTMLInputElement;
        fireEvent.change(input, { target: { files: [file(SPKI_PEM, 'public.pem')] } });
        await waitFor(() => expect(screen.getByLabelText('Public key', { selector: 'textarea' })).toHaveValue(SPKI_PEM));
        expect(screen.getByText('Detected format: PEM (SPKI)')).toBeInTheDocument();
    });

    it('takes a file dropped on the field, and says what is wrong with one that cannot be a key', async () => {
        render(<FormVerify />);
        const field = screen.getByLabelText('Public key', { selector: 'textarea' });
        fireEvent.drop(field, { dataTransfer: { files: [file(PUBLIC_HEX)], types: ['Files'] } });
        await waitFor(() => expect(field).toHaveValue(PUBLIC_HEX));

        fireEvent.drop(field, { dataTransfer: { files: [file(new Uint8Array(5).fill(0xff), 'junk.bin')], types: ['Files'] } });
        expect(await screen.findByText(/junk.bin is not text/)).toBeInTheDocument();
        expect(field).toHaveValue(PUBLIC_HEX); // untouched
        fireEvent.input(field, { target: { value: 'x' } });
        expect(screen.queryByText(/junk.bin is not text/)).not.toBeInTheDocument();
    });

    it('opens a raw binary signature as hex', async () => {
        render(<FormVerify />);
        const signature = new Uint8Array(64).fill(0x91);
        fireEvent.change(screen.getByLabelText('File for signature'), { target: { files: [file(signature, 'message.sig')] } });
        await waitFor(() => expect(screen.getByLabelText('Signature', { selector: 'textarea' })).toHaveValue(bytesToHex(signature)));
    });

    it('saves the public key in the format it is shown in', async () => {
        const saved = captureDownloads();
        render(<FormVerify publicKey={SPKI_PEM} />);
        fireEvent.click(screen.getByRole('button', { name: 'Download public key' }));
        expect(saved.map((s) => s.name)).toEqual(['public.pem']);
        expect(await saved[0].text).toBe(SPKI_PEM);
    });

    it('saves a private key only when asked, and reminds that the file is not encrypted', async () => {
        const saved = captureDownloads();
        render(<FormSign privateKey={SEED_HEX} />);
        expect(saved).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: 'Download private key' }));
        expect(saved.map((s) => s.name)).toEqual(['private-key.txt']);
        expect(await saved[0].text).toBe(`${SEED_HEX}\n`);
        expect(screen.getByRole('status')).toHaveTextContent('This file is not encrypted');
        // typing again clears the reminder
        fireEvent.input(screen.getByLabelText('Private key', { selector: 'textarea' }), { target: { value: SEED_HEX.slice(1) } });
        expect(screen.queryByRole('status')).not.toBeInTheDocument();
    });

    it('has nothing to save while a field is empty', () => {
        render(<FormSign />);
        expect(screen.getByRole('button', { name: 'Download private key' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Download deduced public key' })).toBeDisabled();
    });
});
