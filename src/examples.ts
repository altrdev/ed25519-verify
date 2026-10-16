/**
 * Examples to try the tool with: the test vectors of RFC 8032, section 7.1 (hex, as published), and one signature that is only
 * valid under the permissive ZIP215 rules. The tests check every one against the library, so the values cannot drift.
 */
import { MessageFormat } from './enum';
import type { Verdict } from './signature';

export const RFC_8032_URL = 'https://www.rfc-editor.org/rfc/rfc8032#section-7.1';

export interface Example {
    title: string;
    /** what to notice */
    note: string;
    /** the private key (the 32-byte seed), when the example has one: the Sign tab can reproduce the signature */
    privateKey?: string;
    publicKey: string;
    message: string;
    messageFormat: MessageFormat;
    signature: string;
    /** what the Verify tab must answer */
    verdict: Verdict;
    /** a reference that the example comes from */
    source: string;
}

const RFC_SOURCE = RFC_8032_URL;

export const EXAMPLES: Example[] = [
    {
        title: 'RFC 8032 test 1',
        note: 'The empty message.',
        privateKey: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
        publicKey: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        message: '',
        messageFormat: MessageFormat.Hex,
        signature:
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        verdict: 'valid',
        source: RFC_SOURCE,
    },
    {
        title: 'RFC 8032 test 2',
        note: 'A one byte message (0x72, shown as hex).',
        privateKey: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
        publicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
        message: '72',
        messageFormat: MessageFormat.Hex,
        signature:
            '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
        verdict: 'valid',
        source: RFC_SOURCE,
    },
    {
        title: 'RFC 8032 test 3',
        note: 'A two byte message (0xaf82, shown as hex).',
        privateKey: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
        publicKey: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
        message: 'af82',
        messageFormat: MessageFormat.Hex,
        signature:
            '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
        verdict: 'valid',
        source: RFC_SOURCE,
    },
    {
        title: 'Only valid under ZIP215',
        note: 'The identity point as public key and R, S = 0. The permissive ZIP215 rules (used by Zcash and others) accept it for any message; the strict RFC 8032 rules do not.',
        publicKey: `01${'00'.repeat(31)}`,
        message: 'any message at all',
        messageFormat: MessageFormat.Text,
        signature: `01${'00'.repeat(31)}${'00'.repeat(32)}`,
        verdict: 'permissive-only',
        source: 'https://zips.z.cash/zip-0215',
    },
];

/** The examples that have a private key, for the Sign tab. */
export const SIGNABLE_EXAMPLES = EXAMPLES.filter((example) => example.privateKey);

/** What the note under the "Load example" button says: which example, what to notice, where it comes from. */
export type ExampleInfo = Pick<Example, 'title' | 'note' | 'source'>;

export interface JwsExample extends ExampleInfo {
    token: string;
    /** a JWK, the form in which JOSE tools exchange public keys */
    publicKey: string;
    /** for the Create tab: what makes the token above when signed */
    privateKey: string;
    header: string;
    payload: string;
    verdict: Verdict;
}

const RFC_8037_KEY = {
    privateKey: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    publicKey: '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
};

export const JWS_EXAMPLES: JwsExample[] = [
    {
        title: 'RFC 8037 appendix A.4',
        note: 'The example token of the specification, signed with the key of RFC 8032 test 1.',
        ...RFC_8037_KEY,
        token: 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg',
        header: '{"alg":"EdDSA"}',
        payload: 'Example of Ed25519 signing',
        verdict: 'valid',
        source: 'https://www.rfc-editor.org/rfc/rfc8037#appendix-A.4',
    },
    {
        title: 'A JWT that has expired',
        note: 'Correctly signed, but its "exp" is in the past: the signature is valid and the token says it expired. Made for this page with the same key.',
        ...RFC_8037_KEY,
        token: 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZGEiLCJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaWF0Ijo5NDY2ODQ4MDAsImV4cCI6OTc4MzA3MjAwfQ.R1kbxsH5bPdgymTg-qVwuVxCplHP8MsNlt-mqhxYk4MV8i4lninmk7Ae9gPY5vSt1jdlnIzfRNUyvYfFgUwqDg',
        header: '{"alg":"EdDSA","typ":"JWT"}',
        payload: '{"sub":"ada","name":"Ada Lovelace","iat":946684800,"exp":978307200}',
        verdict: 'valid',
        source: 'https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4',
    },
];

export interface SshsigExample extends ExampleInfo {
    signature: string;
    /** the key to trust, as an authorized_keys line */
    publicKey: string;
    namespace: string;
    message: string;
    hashAlgorithm: 'sha256' | 'sha512';
    /** for the Create tab: what makes the signature above when signing */
    privateKey: string;
}

// made with `ssh-keygen -Y sign` (OpenSSH 9.6) for a key created for these examples: it protects nothing
const SSH_EXAMPLE_KEY = {
    publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAyj+hwReHmoTLUCU/tIuzHePLxf/02FWL/L7jy/874Z fixture@example',
    privateKey:
        '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACAMo/ocEXh5qEy1AlP7SLsx3jy8X/9NhVi/y+48v/O+GQAAAJg7rttQO67b\nUAAAAAtzc2gtZWQyNTUxOQAAACAMo/ocEXh5qEy1AlP7SLsx3jy8X/9NhVi/y+48v/O+GQ\nAAAEDUDBx3weWroYuhBDFhHHT5Nm00pYoVbU193SycVVdCMAyj+hwReHmoTLUCU/tIuzHe\nPLxf/02FWL/L7jy/874ZAAAAD2ZpeHR1cmVAZXhhbXBsZQECAwQFBg==\n-----END OPENSSH PRIVATE KEY-----\n',
    message: 'hello world\n',
};

export const SSHSIG_EXAMPLES: SshsigExample[] = [
    {
        title: 'Made by ssh-keygen -Y sign',
        note: 'The signature of the file with the text "hello world", namespace "file" (the default of ssh-keygen), hashed with SHA-512. ssh-keygen -Y verify accepts it.',
        ...SSH_EXAMPLE_KEY,
        namespace: 'file',
        hashAlgorithm: 'sha512',
        signature:
            '-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgDKP6HBF4eahMtQJT+0i7Md48vF\n//TYVYv8vuPL/zvhkAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx\nOQAAAEB1GLc04h4r/PhOYexUxb7AescsAGKkxCdXxWldoo1MnAvS46tPjWUmf3YbvdLTT1\n/OT17qRdQ8DL9EAWgGYroK\n-----END SSH SIGNATURE-----\n',
        source: 'https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig',
    },
    {
        title: 'A signature for git',
        note: 'The same text signed in the namespace "git" with SHA-256, as git does with gpg.format=ssh. Verified under the namespace "file" it would be refused: the namespace is part of what is signed.',
        ...SSH_EXAMPLE_KEY,
        namespace: 'git',
        hashAlgorithm: 'sha256',
        signature:
            '-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgDKP6HBF4eahMtQJT+0i7Md48vF\n//TYVYv8vuPL/zvhkAAAADZ2l0AAAAAAAAAAZzaGEyNTYAAABTAAAAC3NzaC1lZDI1NTE5\nAAAAQDkezKznm2Z9+yt9gnFpN+glRzkoeEBTebya3MNFxHg+dfnkQENZBbh+935cj+0DaZ\nammTAYOg5wH1a3QRrpBgg=\n-----END SSH SIGNATURE-----\n',
        source: 'https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig',
    },
];
