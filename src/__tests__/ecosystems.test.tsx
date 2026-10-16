import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import * as ed from '@noble/ed25519';
import { hexToBytes, bytesToHex } from '../bytes';
import { detectEcosystem, EcosystemError, encodeEcosystemPrivate, encodeEcosystemPublic, parseEcosystemKey } from '../ecosystems';
import { parseStructuredKey } from '../keyformats';
import { encodePrivateKey, encodePublicKey } from '../keyfiles';
import FormSign from '../FormSign';
import FormVerify from '../FormVerify';
import { formatButton, pickFormat, setFormats } from './helpers';
import { PUBLIC_HEX, SEED_HEX } from './fixtures/keys';

const seed = hexToBytes(SEED_HEX);
const pub = hexToBytes(PUBLIC_HEX);

// written by an independent implementation (Python: hashlib.sha3_256, hand-made CRC16 and base58) for the key of the fixtures
const DID = 'did:key:z6Mkkt6VA7EU72r3UePUavaMqxkSS9cjFTpsazVL8a7Tweu2';
const STELLAR_PUBLIC = 'GBPYFVKKNDJDS6PJOVUGNNVZBTRHP3ZU4HK5V3BYOHCUBHKWGUNI2PUP';
const STELLAR_SECRET = 'SABO7KNPWEYE5KSNCBRYZEZ55TSRTQ465HHJ4EGYBE6SDDXHTEQXUKCJ';
const ONION = 'l6bnksti2i4xt2lvnbtlnoim4j366nhb2xnoyodryvaj2vrvdkg35dyd.onion';
const NEAR_PUBLIC = 'ed25519:7RqSZrz2mVMaN9YmuMcWzsCScaLsqaaWtyaQJJ9T2S7e';
const NEAR_SECRET = 'ed25519:4QUoCyYNkcsyhqjcRtfNygRcmiAkw791n3m9NffpFh14pmhc6vkAiYWPWAQRMDbUcxuxKeBUCWDfsxuw9qXHKoz';

const same = (a: Uint8Array | undefined, b: Uint8Array) => expect(Array.from(a ?? [])).toEqual(Array.from(b));

describe('ecosystem formats', () => {
    it('are written as the reference implementation writes them', () => {
        expect(encodeEcosystemPublic(pub, 'didkey')).toBe(DID);
        expect(encodeEcosystemPublic(pub, 'stellar')).toBe(STELLAR_PUBLIC);
        expect(encodeEcosystemPrivate(seed, pub, 'stellar')).toBe(STELLAR_SECRET);
        expect(encodeEcosystemPublic(pub, 'onion')).toBe(ONION);
        expect(encodeEcosystemPublic(pub, 'near')).toBe(NEAR_PUBLIC);
        expect(encodeEcosystemPrivate(seed, pub, 'near')).toBe(NEAR_SECRET);
        expect(encodeEcosystemPrivate(seed, pub, 'solana')).toBe(`[${[...seed, ...pub].join(', ')}]`);
    });

    it('are read back', () => {
        same(parseEcosystemKey(DID).publicKey, pub);
        same(parseEcosystemKey(STELLAR_PUBLIC).publicKey, pub);
        same(parseEcosystemKey(STELLAR_SECRET).privateKey, seed);
        same(parseEcosystemKey(ONION).publicKey, pub);
        same(parseEcosystemKey(NEAR_PUBLIC).publicKey, pub);
        same(parseEcosystemKey(NEAR_SECRET).privateKey, seed);
        same(parseEcosystemKey(NEAR_SECRET).publicKey, pub);
    });

    it('agree with published vectors', async () => {
        // the example of the W3C did:key method, and the example seed of the Stellar documentation
        const w3c = parseEcosystemKey('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK').publicKey!;
        expect(encodeEcosystemPublic(w3c, 'didkey')).toBe('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
        const stellarSeed = parseEcosystemKey('SAV76USXIJOBMEQXPANUOQM6F5LIOTLPDIDVRJBFFE2MDJXG24TAPUU7').privateKey!;
        expect(encodeEcosystemPublic(await ed.getPublicKeyAsync(stellarSeed), 'stellar')).toBe(
            'GCFXHS4GXL6BVUCXBWXGTITROWLVYXQKQLF4YH5O5JT3YZXCYPAFBJZB',
        );
    });

    it('accept the usual ways of writing them', () => {
        same(parseEcosystemKey(`  ${DID}#${DID.slice(8)}\n`).publicKey, pub);
        same(parseEcosystemKey(`http://${ONION}/path`).publicKey, pub);
        same(parseEcosystemKey(`www.${ONION.toUpperCase()}`).publicKey, pub);
        expect(detectEcosystem('hello')).toBeNull();
        expect(detectEcosystem(PUBLIC_HEX)).toBeNull();
    });

    it('refuse a mistyped or foreign key with the reason', () => {
        const change = (text: string, at: number) =>
            text.slice(0, at) + (text[at] === 'A' || text[at] === 'a' ? 'B' : text[at] === 'b' ? 'c' : 'A') + text.slice(at + 1);
        expect(() => parseEcosystemKey(change(STELLAR_PUBLIC, 20))).toThrow(/checksum/);
        expect(() => parseEcosystemKey(change(ONION, 20))).toThrow(EcosystemError);
        expect(() => parseEcosystemKey('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme')).toThrow(/not an Ed25519/);
        expect(() => parseEcosystemKey('ed25519:3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')).toThrow(/expected 32/);
        expect(() => parseEcosystemKey('did:key:abc')).toThrow(EcosystemError);
        // the Stellar addresses of other kinds (muxed M…, pre-auth T…) are not matched at all
        expect(detectEcosystem(`M${STELLAR_PUBLIC.slice(1)}`)).toBeNull();
    });

    it('never come out as another key (random seeds, every format)', async () => {
        for (let i = 0; i < 60; i++) {
            const s = ed.utils.randomSecretKey();
            const p = await ed.getPublicKeyAsync(s);
            for (const format of ['didkey', 'stellar', 'onion', 'near'] as const) {
                same(parseStructuredKey(encodePublicKey(p, format)).publicKey, p);
            }
            for (const format of ['stellar', 'near'] as const) same(parseStructuredKey(encodePrivateKey(s, p, format)).privateKey, s);
            expect(bytesToHex(parseStructuredKey(encodePublicKey(p, 'onion')).publicKey!)).toBe(bytesToHex(p));
        }
    });
});

describe('ecosystem formats in the forms', () => {
    beforeEach(() => setFormats('hex'));
    const value = (label: string) => (screen.getByLabelText(label) as HTMLTextAreaElement).value;

    it('convert a public key', () => {
        render(<FormVerify publicKey={PUBLIC_HEX} />);
        for (const [format, text] of [
            ['didkey', DID],
            ['stellar', STELLAR_PUBLIC],
            ['onion', ONION],
            ['near', NEAR_PUBLIC],
        ] as const) {
            pickFormat('Public key format', format);
            expect(value('Public key')).toBe(text);
            expect(formatButton('Public key format')).toHaveAccessibleName(/^Public key format: /);
        }
        pickFormat('Public key format', 'hex');
        expect(value('Public key')).toBe(PUBLIC_HEX);
    });

    it('convert a private key, and read a Solana keypair file back as such', async () => {
        render(<FormSign privateKey={SEED_HEX} />);
        for (const [format, text] of [
            ['stellar', STELLAR_SECRET],
            ['near', NEAR_SECRET],
            ['solana', `[${[...seed, ...pub].join(', ')}]`],
        ] as const) {
            pickFormat('Private key format', format);
            await waitFor(() => expect(value('Private key')).toBe(text));
        }
        expect(formatButton('Private key format')).toHaveTextContent('Solana');
        expect(value('Deduced Public key')).toBe(PUBLIC_HEX);
    });

    it('offer each ecosystem only where it exists', () => {
        render(<FormSign />);
        fireEvent.click(formatButton('Private key format'));
        const names = Array.from(document.querySelectorAll('[role="menuitemradio"]')).map((el) => el.getAttribute('data-format'));
        expect(names).toEqual(expect.arrayContaining(['stellar', 'near', 'solana']));
        expect(names).not.toContain('didkey');
        expect(names).not.toContain('onion');
    });
});
