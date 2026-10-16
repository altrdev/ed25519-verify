import { bytesToHex } from '../bytes';
import { sha3_256 } from '../sha3';

// made with Python's hashlib.sha3_256 over the bytes i % 251 (lengths around the 136-byte block of the sponge)
const VECTORS: [number, string][] = [
        [0, 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'],
        [1, '5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0'],
        [32, '050a48733bd5c2756ba95c5828cc83ee16fabcd3c086885b7744f84a0f9e0d94'],
        [135, 'fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2'],
        [136, 'cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5'],
        [137, 'ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca'],
        [272, 'b7ccd55b6c2c3fa144c9e0624059294975a348b02f321abe289701d3012f7794'],
        [300, '4be64d77dff18f218eeb40368f86ed78e6d4f2381c71675ab5ada46aa4fee621'],
];

describe('sha3_256', () => {
    it.each(VECTORS)('hashes %i bytes like hashlib', (length, expected) => {
        expect(bytesToHex(sha3_256(Uint8Array.from({ length }, (_, i) => i % 251)))).toBe(expected);
    });

    it('hashes "abc" (FIPS 202 example)', () => {
        expect(bytesToHex(sha3_256(new TextEncoder().encode('abc')))).toBe('3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
    });
});
