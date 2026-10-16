import { defineConfig, devices } from '@playwright/test';

// The tests run against the production build (the real CSP and service worker), served by `vite preview`: run `npm run build` first.
// PLAYWRIGHT_CHROMIUM_PATH points to an installed Chromium when the one Playwright downloads is not available.
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_PATH;

export default defineConfig({
    testDir: './e2e',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 1 : 0,
    reporter: process.env.CI ? 'github' : 'list',
    use: {
        baseURL: 'http://localhost:4173',
        trace: 'retain-on-failure',
        permissions: ['clipboard-read', 'clipboard-write'],
    },
    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'], launchOptions: executablePath ? { executablePath } : {} },
        },
    ],
    webServer: {
        command: 'npx vite preview --port 4173 --strictPort',
        url: 'http://localhost:4173',
        reuseExistingServer: !process.env.CI,
    },
});
