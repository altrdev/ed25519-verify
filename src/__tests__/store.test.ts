// The preferences are read once, when the module is loaded: each test loads it again, from a prepared localStorage.
const load = async () => {
    vi.resetModules();
    return import('../store');
};

describe('Format preferences', () => {
    beforeEach(() => localStorage.clear());

    it('start as base64 for every result', async () => {
        const { formatPreference } = await load();
        expect([formatPreference.publicKey.value, formatPreference.privateKey.value, formatPreference.signature.value])
            .toEqual(['base64', 'base64', 'base64']);
    });

    it('carry over the single choice of earlier versions', async () => {
        localStorage.setItem('encoding', 'hex');
        const { formatPreference } = await load();
        expect([formatPreference.publicKey.value, formatPreference.privateKey.value, formatPreference.signature.value])
            .toEqual(['hex', 'hex', 'hex']);
    });

    it('are saved for each result, and restored', async () => {
        const first = await load();
        first.formatPreference.signature.value = 'base58';
        first.formatPreference.publicKey.value = 'bytes';
        expect(JSON.parse(localStorage.getItem('formats')!)).toEqual({ publicKey: 'bytes', privateKey: 'base64', signature: 'base58' });

        const second = await load();
        expect(second.formatPreference.signature.value).toBe('base58');
        expect(second.formatPreference.publicKey.value).toBe('bytes');
        expect(second.formatPreference.privateKey.value).toBe('base64');
    });

    it('ignore a saved value that is not a format, or not even JSON', async () => {
        localStorage.setItem('formats', JSON.stringify({ publicKey: 'rot13', privateKey: 42, signature: 'hex' }));
        let { formatPreference } = await load();
        expect([formatPreference.publicKey.value, formatPreference.privateKey.value, formatPreference.signature.value])
            .toEqual(['base64', 'base64', 'hex']);

        localStorage.setItem('formats', '{not json');
        ({ formatPreference } = await load());
        expect(formatPreference.signature.value).toBe('base64');
    });
});
