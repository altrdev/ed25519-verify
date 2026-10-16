/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from 'vite';
import preact from '@preact/preset-vite';
import { VitePWA } from 'vite-plugin-pwa';
import pkg from './package.json' with { type: 'json' };
import { CONTENT_SECURITY_POLICY } from './src/csp.ts';

// the version shown in the footer is the one of package.json, so `npm version` is the only place to change
const { version } = pkg;

// Production build only: the dev server needs inline scripts and a WebSocket for hot reload.
// It goes first in <head> because a <meta> policy only applies to what comes after it.
const contentSecurityPolicy = (): Plugin => ({
    name: 'content-security-policy',
    apply: 'build',
    transformIndexHtml: () => [
        {
            tag: 'meta',
            attrs: { 'http-equiv': 'Content-Security-Policy', content: CONTENT_SECURITY_POLICY },
            injectTo: 'head-prepend',
        },
    ],
});

export default defineConfig({
    // relative base: works on GitHub Pages under /ed25519-verify/ and anywhere else
    base: './',
    define: { __APP_VERSION__: JSON.stringify(version) },
    plugins: [
        preact(),
        contentSecurityPolicy(),
        VitePWA({
            registerType: 'autoUpdate',
            manifest: false, // public/manifest.webmanifest is used as is
            includeAssets: [
                'favicon.svg',
                'favicon.png',
                'favicon-32.png',
                'manifest.webmanifest',
                'images/icons/apple/apple-touch-icon-180-180.png',
            ],
        }),
    ],
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./src/test-setup.ts'],
    },
});
