import html from '../../index.html?raw';

const meta = (attr: 'property' | 'name', key: string) => new RegExp(`<meta ${attr}="${key}" content="([^"]*)"`).exec(html)?.[1];

describe('link preview (Open Graph / Twitter card)', () => {
    it('describes the site with absolute URLs, which the platforms require', () => {
        expect(meta('property', 'og:title')).toBeTruthy();
        expect(meta('property', 'og:description')).toBeTruthy();
        expect(meta('property', 'og:url')).toBe('https://ed25519.altr.dev/');
        expect(meta('property', 'og:image')).toBe('https://ed25519.altr.dev/og-image.png');
        expect(meta('name', 'twitter:image')).toBe('https://ed25519.altr.dev/og-image.png');
        expect(meta('name', 'twitter:card')).toBe('summary_large_image');
        expect(meta('name', 'description')).toBeTruthy();
    });
});
