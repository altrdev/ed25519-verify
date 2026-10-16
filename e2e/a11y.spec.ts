import AxeBuilder from '@axe-core/playwright';
import { expect, type Page, test } from '@playwright/test';
import { JWS, panel, pickFormat, RFC } from './helpers';

// WCAG 2.1 A and AA plus axe's best practices, in both themes, with each kind of content on screen.
const check = async (page: Page) => {
    const { violations } = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice']).analyze();
    const summary = violations.map(
        (v) => `${v.id} (${v.impact}): ${v.help}\n${v.nodes.map((n) => `    ${n.target.join(' ')}\n    ${n.failureSummary}`).join('\n')}`,
    );
    expect(summary, summary.join('\n\n')).toEqual([]);
};

for (const theme of ['light', 'dark'] as const) {
    test.describe(`${theme} theme`, () => {
        test.beforeEach(async ({ page }) => {
            await page.addInitScript((value) => localStorage.setItem('theme', value), theme);
            await page.goto('/');
            await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        });

        test('verify tab, empty', async ({ page }) => {
            await check(page);
        });

        test('verify tab, with errors', async ({ page }) => {
            await panel(page).getByLabel('Public key', { exact: true }).fill('abcd');
            await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(panel(page).getByText(/expected 32 bytes/i)).toBeVisible();
            await check(page);
        });

        test('verify tab, valid and wrong results', async ({ page }) => {
            await panel(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
            await panel(page).getByRole('group', { name: 'Message format' }).getByRole('button', { name: 'Hex' }).click();
            await panel(page).getByLabel('Message', { exact: true }).fill(RFC.messageHex);
            await panel(page).getByLabel('Signature', { exact: true }).fill(RFC.signature);
            await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(panel(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            await panel(page).getByLabel('Message', { exact: true }).fill('73');
            await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(panel(page).getByText('Signature is wrong')).toBeVisible();
            await check(page);
        });

        test('verify tab, wrong signature with hints', async ({ page }) => {
            // the RFC vector with the message typed as text "r" read as hex: the hint says so
            await panel(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
            await panel(page).getByLabel('Message', { exact: true }).fill('72');
            await panel(page).getByLabel('Signature', { exact: true }).fill(RFC.signature);
            await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(panel(page).getByRole('region', { name: 'Why it may be wrong' })).toBeVisible();
            await check(page);
        });

        test('examples, valid and ZIP215', async ({ page }) => {
            const load = panel(page).getByRole('button', { name: 'Load example' });
            await load.click();
            await expect(panel(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            for (let i = 0; i < 3; i++) await load.click();
            await expect(panel(page).getByText('Only valid under ZIP215.')).toBeVisible();
            await check(page);
        });

        test('sign tab, example with the published signature', async ({ page }) => {
            await page.getByRole('tab', { name: 'Sign message' }).click();
            await panel(page).getByRole('button', { name: 'Load example' }).click();
            await panel(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(panel(page).getByText('Identical to the signature published in RFC 8032.')).toBeVisible();
            await check(page);
        });

        test('key fields with Download and Choose file, and the saved-file reminder', async ({ page }) => {
            await page.getByRole('tab', { name: 'Sign message' }).click();
            await panel(page).getByRole('button', { name: 'Load example' }).click();
            await panel(page).getByRole('button', { name: 'Download private key' }).click();
            await expect(panel(page).getByRole('status')).toBeVisible();
            await check(page);
        });

        test('signed formats, a token verified', async ({ page }) => {
            await page.getByRole('tab', { name: 'Signed formats' }).click();
            await panel(page).getByLabel('Token', { exact: true }).fill(JWS.token);
            await panel(page).getByLabel('Public key', { exact: true }).fill(JWS.jwkPublic);
            await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(panel(page).getByRole('region', { name: 'Token contents' })).toBeVisible();
            await check(page);
        });

        test('signed formats, a token with an error, and creating one', async ({ page }) => {
            await page.getByRole('tab', { name: 'Signed formats' }).click();
            await panel(page).getByLabel('Token', { exact: true }).fill('a.b');
            await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(panel(page).getByText(/three parts/)).toBeVisible();
            await check(page);
            await panel(page).getByRole('button', { name: 'Create a token' }).click();
            await panel(page).getByLabel('Private key', { exact: true }).fill(JWS.privateKeyHex);
            await panel(page).getByLabel('Payload', { exact: true }).fill('{"sub":"ada"}');
            await panel(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(panel(page).locator('.result')).not.toBeEmpty();
            await check(page);
        });

        test('format menu open', async ({ page }) => {
            await panel(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
            await page.getByRole('button', { name: /^Public key format:/ }).click();
            await expect(page.getByRole('menu')).toBeVisible();
            await check(page);
        });

        test('choice between two readings', async ({ page }) => {
            // a 43-character base58 key that is also valid base64
            await panel(page).getByLabel('Public key', { exact: true }).fill('MHMb3k7Hjcn1ZedZZy2CWMJjiRiJrVD9zNm96cPpHke');
            await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(
                panel(page)
                    .getByRole('button', { name: /^Read as/ })
                    .first(),
            ).toBeVisible();
            await check(page);
        });

        test('sign tab, with a result', async ({ page }) => {
            await page.getByRole('tab', { name: 'Sign message' }).click();
            await panel(page).getByRole('button', { name: 'Generate' }).click();
            await panel(page).getByLabel('Message', { exact: true }).fill('accessibility');
            await panel(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(panel(page).locator('.result')).not.toBeEmpty();
            await pickFormat(page, 'Signature format', 'hex');
            await check(page);
        });
    });
}
