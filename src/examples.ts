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
    {
        title: 'A token and the key set of its issuer',
        note: 'The public key is a JWK Set with two Ed25519 keys and an RSA one. The token names "key-2" in its header (kid), so that key is picked from the set; the RSA key is left out. Made for this page.',
        privateKey: '6b775269140d487bed9fd684816ef7d86543b14fbb9a56d033ef0cddc604d3b7',
        publicKey:
            '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"key-1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},{"kty":"OKP","crv":"Ed25519","kid":"key-2","x":"HTAZSIhmy0zYZuoxA9tij6796Ai6Sm-_uDVPqvzc5Uw"},{"kty":"RSA","kid":"rsa-1","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTMjAsrEzaCQmpjoA","e":"AQAB"}]}',
        token: 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoiYWRhIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9.3O1u5UllX-hUsB6jmezhrZJiY6Z1yrOYNyYil4dstJuaOakveQP_VfsxvIHiYVBgx_dr5Q2pdayHENZ9GPMyBA',
        header: '{"alg":"EdDSA","typ":"JWT","kid":"key-2"}',
        payload: '{"iss":"https://issuer.example","sub":"ada","iat":1700000000,"exp":4102444800}',
        verdict: 'valid',
        source: 'https://www.rfc-editor.org/rfc/rfc7517#section-5',
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

export interface MinisignExample extends ExampleInfo {
    signature: string;
    /** the key to trust: the content of a minisign `.pub` file */
    publicKey: string;
    message: string;
    trustedComment: string;
    /** for the Create tab: the key and its id, which make the signature above when signing (only for the hashed form) */
    privateKey: string;
    keyId: string;
}

// made with minisign 0.11 (`minisign -G -W`, `minisign -S`) for a key created for these examples: it protects nothing
const MINISIGN_EXAMPLE_KEY = {
    publicKey: 'untrusted comment: minisign public key B74960C202F410C9\nRWTJEPQCwmBJt134g5TvjpQuUaPfSyDKhTo8dp2OlM9YDzgm24kHbykm\n',
    privateKey: 'f1ac93937869f682a585b20db4be66d84ff090c82f42914e69952c649a32c75e',
    keyId: 'B74960C202F410C9',
    message: 'hello world\n',
};

export const MINISIGN_EXAMPLES: MinisignExample[] = [
    {
        title: 'Made by minisign',
        note: 'The signature of the text "hello world" with a trusted comment, in the form minisign writes by default: it signs the BLAKE2b-512 hash of the message. minisign -V accepts it.',
        ...MINISIGN_EXAMPLE_KEY,
        trustedComment: 'timestamp:1700000000\tfile:msg.txt',
        signature:
            'untrusted comment: signature from minisign secret key\nRUTJEPQCwmBJt1+ho+eXhWVFgLEF3cIAf1KYknPR+0wnBDrSAOc0dX6/6zfCPVq2btUddi6bxZ+d1ill9L/KIE3hUWANdJywcgo=\ntrusted comment: timestamp:1700000000\tfile:msg.txt\n4Z9h8bxCC1lNqEdCSrAPwD8Of9rHLqWq/JWt7Ckn7S4wg0IhKDcgiISy4mejS5me/EKLlbhptrAN0lTh5AvPAA==\n',
        source: 'https://jedisct1.github.io/minisign/#signature-format',
    },
    {
        title: 'A legacy signature',
        note: 'The same text signed with minisign -l, the older form that signs the message itself instead of its hash ("Ed" instead of "ED"). Still accepted by minisign.',
        ...MINISIGN_EXAMPLE_KEY,
        trustedComment: 'legacy one',
        signature:
            'untrusted comment: signature from minisign secret key\nRWTJEPQCwmBJtx3h7m6cUL7+aIl1v3uuE+mu8hjAfoGsuZH0RJxCCBvNJjuvb0SA5YAZBKq8AD84FGU+Rict3kIaQ2Z2nKuAcgY=\ntrusted comment: legacy one\neSHtuzBqUO+7uYe7nX90XkbRDuPesCjh7edvpj/IJSOHc1YdSfBczgXi2yquCemvjVK1pfKkqCRDT4b7tKMkCA==\n',
        source: 'https://jedisct1.github.io/minisign/#signature-format',
    },
];

export interface CoseExample extends ExampleInfo {
    /** the COSE_Sign1, as hex */
    message: string;
    publicKey: string;
    /** the payload typed, when the message has none */
    payload: string;
    externalData: string;
    /** for the Create tab: what makes the message above when signing */
    privateKey: string;
    kid: string;
    contentType: string;
    detached: boolean;
}

// the key of RFC 8032 test 1, as in the examples of the COSE working group
const COSE_EXAMPLE_KEY = {
    publicKey: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    privateKey: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
};

export const COSE_EXAMPLES: CoseExample[] = [
    {
        title: 'EdDSA-01 of the COSE working group',
        note: 'The example "EdDSA-01" of the COSE working group: the text "This is the content." signed with the key of RFC 8032 test 1, a key id and a content type. The signature is the published one.',
        ...COSE_EXAMPLE_KEY,
        message:
            'd28445a201270300a10442313154546869732069732074686520636f6e74656e742e58407142fd2ff96d56db85bee905a76ba1d0b7321a95c8c4d3607c5781932b7afb8711497dfa751bf40b58b3bcc32300b1487f3db34085eef013bf08f4a44d6fef0d',
        payload: 'This is the content.',
        externalData: '',
        kid: '11',
        contentType: '0',
        detached: false,
        source: 'https://github.com/cose-wg/Examples/blob/master/eddsa-examples/eddsa-sig-01.json',
    },
    {
        title: 'A payload that travels apart',
        note: 'The payload is nil in the message and is given in the Payload field; the signature also covers the external data "context", which the message does not carry. Without either the signature is wrong. Made with pycose.',
        ...COSE_EXAMPLE_KEY,
        message:
            'd28443a10127a0f658407d2d0085f5d876bd11ad188ce6de2b96ab5b84a40d2ef0c6bdc5a228d126eda0ca6c319dd868081cb6d5b2b76520a5a923aa5dc2fbf1d2b1e2c6ff5afb39e603',
        payload: 'hello world',
        externalData: 'context',
        kid: '',
        contentType: '',
        detached: true,
        source: 'https://www.rfc-editor.org/rfc/rfc9052#name-signing-and-verification-pro',
    },
];

export interface PgpExample extends ExampleInfo {
    /** an armored signature, or a whole cleartext signed message */
    signature: string;
    publicKey: string;
    /** empty for a cleartext signed message */
    message: string;
}

// made with GnuPG 2.4 and Sequoia (see the tests) for keys created for these examples: they protect nothing
const PGP_KEY =
    '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEatKITxYJKwYBBAHaRw8BAQdA13UAjhhk5pUFY9QeSlh17mRN8jek88HAoDed\nbsK0MkG0HUZpeHR1cmUgPGZpeHR1cmVAZXhhbXBsZS5jb20+iJMEExYKADsWIQQz\njfpOoyLPhzRj6POBCIU3IlJhUwUCatKITwIbAwULCQgHAgIiAgYVCgkICwIEFgID\nAQIeBwIXgAAKCRCBCIU3IlJhU1CZAQCZubRewnN0U/zWbizUweFsI0rhYj87Eet5\nG5Zo6e34lwD+O5ySz37OhiowiOtoVRL8IgcZpKB26w/kikLnmm3Uugy4MwRq0ohW\nFgkrBgEEAdpHDwEBB0CoRCWD4RNovRac/I5LpNLwgD5ph71I4l2JYcNYbSchq4jv\nBBgWCgAgFiEEM436TqMiz4c0Y+jzgQiFNyJSYVMFAmrSiFYCGwIAgQkQgQiFNyJS\nYVN2IAQZFgoAHRYhBL11FxbxR+Ec17JI66Ucvwx5p80JBQJq0ohWAAoJEKUcvwx5\np80Jf7YA/AzLXxkjrmjUVlV0ZsCGwxFsugO2QCOLMcMnqIIfNlJEAQC8uXQFW1T5\nDgFuWOJRSAAKx5eX14TGH26VBKRaJcBQDUWSAQCKubSj7fqrjcTFIhkD+3rpw+a+\nLvr6Yw6FqsrGhQI0xwEA6wBf/gXC2aha9ciRy7MJFvuB01InFXjh+7WI3APyaQI=\n=+uMq\n-----END PGP PUBLIC KEY BLOCK-----\n';
const PGP_KEY_V6 =
    '-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: 21C9 3D92 4F7E 0D74 127E 1B36 B8BB 7FE2  879C 4B25 F024 D6EA A5B2 4597 3439 798B\nComment: Fixture V6 <v6@example.com>\n\nxioGatKIkhsAAAAg7E7Gko0h89cb7yLHTvYSWwi2fsbfExl1+S3W7UmzxrnCpgYf\nGwoAAAA3BYJq0oiSAwsJBwMVCggCmwECHgkiIQYhyT2ST34NdBJ+Gza4u3/ih5xL\nJfAk1uqlskWXNDl5iwAAAABwXyC+DfMt71A/k/0eReHrQYQkrU6KXLBhhgTl4LEk\nl98O/UH4EtyA5aOWhZz0MwWt3PixnvfKT9mlaKotKK0+eIobbhFoPAcPUf4V2rz/\n9n2VuYECVACxH2RSVo9KnmrTeQDNG0ZpeHR1cmUgVjYgPHY2QGV4YW1wbGUuY29t\nPsKpBhMbCgAAADoFgmrSiJIDCwkHAxUKCAKZAQKbAQIeCSIhBiHJPZJPfg10En4b\nNri7f+KHnEsl8CTW6qWyRZc0OXmLAAAAAP3XIEddh4M5duQuvIY6Z0nZeJfUohb9\nRfRZkVOuO4JdAw3NkvWg36H/HeAPQ5EKzGFXjrn3QdOJpcCAQzSuTAhJoSE2eIE2\n7CUuZie5pzxWexO4piGf6zW2f7KMFi97LOmFD84qBmrSiJIbAAAAIFzVK8ldpiwZ\nyxs/+4byocTq69cqnW3lERZy5qo1QoqowsB1BhgbCgAAAMYFgmrSiJICmwKZoAYZ\nGwoAAAApBYJq0oiSIiEGRBkbAKDqdBIGooWDRiBXwykwXXT9oa7hUpleD3yvLYsA\nAAAAz7IgNXcBc70XRo5qodtjfxZzWY2yPi/tCF+je/AT2n/yv1rf/T9emcKXD/mZ\nBAbmOuZ3/HFDTT2rz9ovGwD6QfUOhcArqKKNpUrOexbcUJeZ+szMb0LrUp0l7xdA\nfWY3ZI0PIiEGIck9kk9+DXQSfhs2uLt/4oecSyXwJNbqpbJFlzQ5eYsAAAAAYnYg\nmlzjtvuN+HgvvrwtrQLXYph2KvhLq15gHIyEUvnoYmf77hmaRVcp4Nk47VU7q5TU\niaWBVqWZDGDIJvHpqJF26z9JXt5XSkcwdRGauj1moMvG4icPB2ST+6W2mCUgDZ0P\n-----END PGP PUBLIC KEY BLOCK-----\n';

export const PGP_EXAMPLES: PgpExample[] = [
    {
        title: 'Made by gpg --detach-sign',
        note: 'The detached signature of the text "hello world", made by the signing subkey of the key below: the signature names the subkey, and the page finds it in the key block. gpg --verify accepts it.',
        publicKey: PGP_KEY,
        message: 'hello world\n',
        signature:
            '-----BEGIN PGP SIGNATURE-----\n\niHUEABYKAB0WIQS9dRcW8UfhHNeySOulHL8MeafNCQUCatKIVgAKCRClHL8MeafN\nCdLIAQDR4c+QMqbejzJHcbzQefDNb/gwYKKddKU/xFoaIoI0EgD/aKSb9GaKdJMP\ng0s2Ee4rnwARePytQtdzZT/T6Lwc1wE=\n=xLFY\n-----END PGP SIGNATURE-----\n',
        source: 'https://www.rfc-editor.org/rfc/rfc4880#section-5.2',
    },
    {
        title: 'A cleartext signed message',
        note: 'What gpg --clearsign writes: the text, readable as it is, followed by its signature. The line that starts with a dash is escaped as "- -" and the spaces at the end of a line are not signed; the page undoes both.',
        publicKey: PGP_KEY,
        message: '',
        signature:
            '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nline one  \nline two\n- - dashed line\n-----BEGIN PGP SIGNATURE-----\n\niHUEARYKAB0WIQS9dRcW8UfhHNeySOulHL8MeafNCQUCatKIVgAKCRClHL8MeafN\nCSYiAQCrdJ5kVpNUlHl+LW9QPONy+fUbA6ga6D8UNjI/hK7SxAEA2EsSUXRpsono\n2vSnfgAyhW9qmt4TInMyoxMSU23V0wk=\n=hJwj\n-----END PGP SIGNATURE-----\n',
        source: 'https://www.rfc-editor.org/rfc/rfc4880#section-7',
    },
    {
        title: 'A version 6 signature (RFC 9580)',
        note: 'The new format of OpenPGP: an Ed25519 key of algorithm 27 with a version 6 fingerprint (SHA-256), and a signature with a salt. Made with Sequoia.',
        publicKey: PGP_KEY_V6,
        message: 'hello world\n',
        signature:
            '-----BEGIN PGP SIGNATURE-----\n\nwpgGABsKAAAAKQWCatKIziIhBiHJPZJPfg10En4bNri7f+KHnEsl8CTW6qWyRZc0\nOXmLAAAAAM7fICgM4deCytgkRsFmTjWUst73gCTxg/6cLqiIcHwjtpz2EkjyAA99\nnALjuBB5C/uHxjYyDNn8G7kE2FL3QmaspUBe1rLNfVDm1k4Fz1IxtTixF+/UReGO\nG0/OfgkHu8sFDQ==\n-----END PGP SIGNATURE-----\n',
        source: 'https://www.rfc-editor.org/rfc/rfc9580',
    },
];
