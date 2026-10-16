import { randomBytes } from 'node:crypto';
import { detectContainer, handoffFor } from '../detect';
import { MessageFormat } from '../enum';
import { JWS_EXAMPLES, MINISIGN_EXAMPLES, PGP_EXAMPLES, SSHSIG_EXAMPLES, COSE_EXAMPLES, EXAMPLES } from '../examples';
import { COSE_ATTACHED, COSE_DETACHED, COSE_PLAIN } from './fixtures/cose';
import { MS_PUBLIC_FILE, MS_SIG_LEGACY } from './fixtures/minisign';
import { PGP_PUBLIC } from './fixtures/openpgp';
import { SSH_PUBLIC } from './fixtures/sshsig';

describe('which container a pasted signature is', () => {
    it('recognises each one by what it is', () => {
        expect(detectContainer(JWS_EXAMPLES[0].token)).toBe('jws');
        expect(detectContainer(`Bearer ${JWS_EXAMPLES[1].token}`)).toBe('jws');
        expect(detectContainer(`  ${JWS_EXAMPLES[1].token}\n`)).toBe('jws');
        expect(detectContainer(SSHSIG_EXAMPLES[0].signature)).toBe('sshsig');
        expect(detectContainer(MINISIGN_EXAMPLES[0].signature)).toBe('minisign');
        expect(detectContainer(MS_SIG_LEGACY)).toBe('minisign');
        expect(detectContainer(PGP_EXAMPLES[0].signature)).toBe('pgp');
        expect(detectContainer(PGP_EXAMPLES[1].signature)).toBe('pgp'); // a cleartext signed message
        for (const hex of [COSE_ATTACHED, COSE_PLAIN, COSE_DETACHED, `d83d${COSE_PLAIN}`]) expect(detectContainer(hex)).toBe('cose');
        expect(detectContainer(Buffer.from(COSE_ATTACHED, 'hex').toString('base64'))).toBe('cose');
        expect(detectContainer(COSE_ATTACHED.replace(/(.{32})/g, '$1\n'))).toBe('cose');
        expect(COSE_EXAMPLES[0].message).toBe(COSE_ATTACHED);
    });

    it('never takes a plain signature for one, in any notation', () => {
        for (const example of EXAMPLES) expect(detectContainer(example.signature)).toBeNull();
        for (let i = 0; i < 200; i++) {
            const bytes = randomBytes(64);
            expect(detectContainer(bytes.toString('hex'))).toBeNull();
            expect(detectContainer(bytes.toString('base64'))).toBeNull();
            expect(detectContainer(bytes.toString('base64url'))).toBeNull();
        }
        // a 64 byte signature that starts like a COSE message is still a signature
        expect(detectContainer(`d284${'00'.repeat(62)}`)).toBeNull();
        expect(detectContainer(`84${'00'.repeat(63)}`)).toBeNull();
    });

    it('does not take keys, random data or other text for one', () => {
        for (const text of [
            '',
            '   ',
            'hello world',
            MS_PUBLIC_FILE,
            PGP_PUBLIC,
            SSH_PUBLIC,
            'a.b.c',
            'eyJ.eyJ.sig',
            '1.2.3',
            randomBytes(300).toString('hex'),
            randomBytes(300).toString('base64'),
        ]) {
            expect(detectContainer(text)).toBeNull();
        }
        // three base64url parts whose first is not a JSON object (a version number, a list)
        const part = (value: string) => Buffer.from(value).toString('base64url');
        expect(detectContainer(`${part('[1,2]')}.${part('x')}.${part('y')}`)).toBeNull();
        expect(detectContainer(`${part('hello')}.${part('x')}.${part('y')}`)).toBeNull();
    });
});

describe('what each container takes from the Verify tab', () => {
    const fields = { signature: ' SIG ', publicKey: 'KEY', message: 'MSG', messageFormat: MessageFormat.Hex };

    it('the signature where it goes, the key, and the message where the format has one', () => {
        expect(handoffFor('jws', fields)).toEqual({ format: 'jws', shared: { token: 'SIG', publicKey: 'KEY' } });
        expect(handoffFor('sshsig', fields)).toEqual({
            format: 'sshsig',
            shared: { signature: 'SIG', publicKey: 'KEY', namespace: '', message: 'MSG', messageFormat: MessageFormat.Hex },
        });
        expect(handoffFor('minisign', fields).shared).toEqual({
            signature: 'SIG',
            publicKey: 'KEY',
            message: 'MSG',
            messageFormat: MessageFormat.Hex,
        });
        expect(handoffFor('pgp', fields).shared).toEqual({
            signature: 'SIG',
            publicKey: 'KEY',
            message: 'MSG',
            messageFormat: MessageFormat.Hex,
        });
        expect(handoffFor('cose', fields).shared).toEqual({
            message: 'SIG',
            publicKey: 'KEY',
            payload: 'MSG',
            payloadFormat: MessageFormat.Hex,
            externalData: '',
        });
    });
});
