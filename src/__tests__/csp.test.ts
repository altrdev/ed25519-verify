import { CONTENT_SECURITY_POLICY, DIRECTIVES } from '../csp';

describe('Content-Security-Policy', () => {
    const sourcesOf = (directive: string) => DIRECTIVES[directive] ?? [];

    it('only lets the page talk to its own origin', () => {
        // 'self' (not 'none') because Chrome downloads the manifest icons under connect-src
        expect(sourcesOf('connect-src')).toEqual(["'self'"]);
        expect(sourcesOf('default-src')).toEqual(["'none'"]);
        expect(sourcesOf('form-action')).toEqual(["'none'"]);
    });

    it('only runs scripts and styles served by the app itself', () => {
        expect(sourcesOf('script-src')).toEqual(["'self'"]);
        expect(sourcesOf('style-src')).toEqual(["'self'"]);
        expect(sourcesOf('worker-src')).toEqual(["'self'"]);
    });

    it('never allows inline code, eval, wildcards or remote hosts', () => {
        for (const sources of Object.values(DIRECTIVES)) {
            for (const source of sources) {
                expect(['unsafe-inline', 'unsafe-eval', 'unsafe-hashes', 'wasm-unsafe-eval'].some((k) => source.includes(k))).toBe(false);
                expect(source).not.toBe('*');
                expect(source).not.toMatch(/^(https?:|\/\/|data:|blob:)/);
            }
        }
    });

    it('serialises to a valid header value', () => {
        expect(CONTENT_SECURITY_POLICY).toMatch(/^default-src 'none'; script-src 'self'/);
        expect(CONTENT_SECURITY_POLICY).toContain("connect-src 'self'");
        expect(CONTENT_SECURITY_POLICY).not.toContain('"');
    });
});
