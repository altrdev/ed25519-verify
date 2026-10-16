/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from 'vite';
import preact from '@preact/preset-vite';
import { VitePWA } from 'vite-plugin-pwa';
import { CONTENT_SECURITY_POLICY } from './src/csp.ts';

// The version shown in the footer is given by the workflow that builds the site (the release, or a manual deploy of a branch);
// a local build is a "dev" one. It is not read from package.json: the tag of the release is the version.
const version = process.env.APP_VERSION || 'dev';

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
        include: ['src/**/*.test.{ts,tsx}'], // e2e/ belongs to Playwright
    },
});
