/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  // relative base: works on GitHub Pages under /ed25519-verify/ and anywhere else
  base: './',
  plugins: [
    preact(),
    VitePWA({
      registerType: 'autoUpdate',
      manifest: false, // public/manifest.webmanifest is used as is
      includeAssets: ['favicon.svg', 'favicon.png', 'favicon-32.png', 'manifest.webmanifest', 'images/icons/apple/apple-touch-icon-180-180.png'],
    }),
  ],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
  },
});
