import { expect, test } from '@playwright/test';
import { collectProblems, panel, pickFormat, RFC } from './helpers';

test.describe('verify and sign', () => {
    test('verifies a signature of the RFC 8032 vectors, and rejects a changed one', async ({ page }) => {
        const problems = collectProblems(page);
        await page.goto('/');
        await panel(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
        await panel(page).getByRole('group', { name: 'Message format' }).getByRole('button', { name: 'Hex' }).click();
        await panel(page).getByLabel('Message', { exact: true }).fill(RFC.messageHex);
        await panel(page).getByLabel('Signature', { exact: true }).fill(RFC.signature);
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText('Signature is valid')).toBeVisible();

        await panel(page).getByLabel('Message', { exact: true }).fill('73');
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText('Signature is wrong')).toBeVisible();
        expect(problems).toEqual([]);
    });

    test('suggests what may be wrong when a signature does not verify', async ({ page }) => {
        await page.goto('/');
        await panel(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
        // the message "72" is hex, but the selector is left on Text
        await panel(page).getByLabel('Message', { exact: true }).fill(RFC.messageHex);
        await panel(page).getByLabel('Signature', { exact: true }).fill(RFC.signature);
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText('Signature is wrong')).toBeVisible();
        await expect(panel(page).getByText('It is valid with the message read as hex (the selector is on Text).')).toBeVisible();
        // the hint is right: switching the selector makes it valid
        await panel(page).getByRole('group', { name: 'Message format' }).getByRole('button', { name: 'Hex' }).click();
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText('Signature is valid')).toBeVisible();
    });

    test('says what is wrong with an input instead of a wrong signature', async ({ page }) => {
        await page.goto('/');
        await panel(page).getByLabel('Public key', { exact: true }).fill('abcd');
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText(/expected 32 bytes/i)).toBeVisible();
    });

    test('signs with the key of a vector and gets the published signature', async ({ page }) => {
        await page.goto('/');
        await page.getByRole('tab', { name: 'Sign message' }).click();
        const sign = panel(page);
        await sign.getByLabel('Private key', { exact: true }).fill(RFC.privateKey);
        await pickFormat(page, 'Public key format', 'hex'); // results are written in base64 by default
        await expect(sign.getByRole('textbox', { name: 'Deduced Public key' })).toHaveValue(RFC.publicKey);
        await sign.getByRole('group', { name: 'Message format' }).getByRole('button', { name: 'Hex' }).click();
        await sign.getByLabel('Message', { exact: true }).fill(RFC.messageHex);
        await sign.getByRole('button', { name: 'Sign', exact: true }).click();
        await pickFormat(page, 'Signature format', 'hex');
        await expect(sign.getByText(RFC.signature)).toBeVisible();
    });

    test('generates a key pair, signs, and the signature verifies', async ({ page }) => {
        await page.goto('/');
        await page.getByRole('tab', { name: 'Sign message' }).click();
        const sign = panel(page);
        await sign.getByRole('button', { name: 'Generate' }).click();
        await expect(sign.getByRole('textbox', { name: 'Deduced Public key' })).not.toHaveValue('');
        await sign.getByLabel('Message', { exact: true }).fill('hello from the e2e test');
        await sign.getByRole('button', { name: 'Sign', exact: true }).click();
        await expect(sign.locator('.result')).not.toBeEmpty();

        const publicKey = await sign.getByRole('textbox', { name: 'Deduced Public key' }).inputValue();
        const signature = await sign.locator('.result').innerText();
        await page.getByRole('tab', { name: 'Verify signature' }).click();
        await panel(page).getByLabel('Public key', { exact: true }).fill(publicKey);
        await panel(page).getByLabel('Message', { exact: true }).fill('hello from the e2e test');
        await panel(page).getByLabel('Signature', { exact: true }).fill(signature);
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText('Signature is valid')).toBeVisible();
    });
});

test.describe('formats', () => {
    test('converts a public key between notations and key files', async ({ page }) => {
        await page.goto('/');
        const field = panel(page).getByLabel('Public key', { exact: true });
        await field.fill(RFC.publicKey);
        await expect(panel(page).getByText('Detected: hex · 32 bytes')).toBeVisible();
        await pickFormat(page, 'Public key format', 'openssh');
        await expect(field).toHaveValue(/^ssh-ed25519 AAAA/);
        await pickFormat(page, 'Public key format', 'pem');
        await expect(field).toHaveValue(/BEGIN PUBLIC KEY/);
        await pickFormat(page, 'Public key format', 'hex');
        await expect(field).toHaveValue(RFC.publicKey);
    });
});

test.describe('share link', () => {
    test('a copied link opens with the fields filled and the answer shown', async ({ page, context }) => {
        await page.goto('/');
        await panel(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
        await panel(page).getByRole('group', { name: 'Message format' }).getByRole('button', { name: 'Hex' }).click();
        await panel(page).getByLabel('Message', { exact: true }).fill(RFC.messageHex);
        await panel(page).getByLabel('Signature', { exact: true }).fill(RFC.signature);
        await panel(page).getByRole('button', { name: 'Copy link to this verification' }).click();
        const link = await page.evaluate(() => navigator.clipboard.readText());
        expect(link).toContain('#');
        expect(link).not.toContain(RFC.privateKey);

        const other = await context.newPage();
        await other.goto(link);
        await expect(panel(other).getByLabel('Public key', { exact: true })).toHaveValue(RFC.publicKey);
        await expect(panel(other).getByText('Signature is valid')).toBeVisible();
    });
});

test.describe('offline and security', () => {
    test('works offline after the first visit', async ({ page, context }) => {
        await page.goto('/');
        await page.evaluate(() => navigator.serviceWorker.ready.then(() => undefined));
        await page.reload(); // the service worker controls the page from the second load
        await context.setOffline(true);
        await page.reload();
        await expect(page.getByRole('heading', { name: /Ed25519/ })).toBeVisible();
        await panel(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
        await expect(panel(page).getByText('Detected: hex · 32 bytes')).toBeVisible();
    });

    test('makes no request to another host and shows the version', async ({ page }) => {
        const hosts = new Set<string>();
        page.on('request', (request) => hosts.add(new URL(request.url()).host));
        const problems = collectProblems(page);
        await page.goto('/');
        await panel(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(page.locator('footer')).toContainText(/\bv\d+\.\d+\.\d+\b|\bdev\b|\bmain-\w+/); // a local or CI build says "dev"
        expect([...hosts]).toEqual(['localhost:4173']);
        expect(problems).toEqual([]);
    });

    test('ships the Content-Security-Policy', async ({ page }) => {
        await page.goto('/');
        const policy = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content');
        expect(policy).toContain("default-src 'none'");
        expect(policy).not.toMatch(/unsafe-(inline|eval)/);
    });
});
