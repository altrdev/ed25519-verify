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
