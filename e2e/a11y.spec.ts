import AxeBuilder from '@axe-core/playwright';
import { expect, type Page, test } from '@playwright/test';
import { JWS, panel, pickFormat, RFC, raw, signed } from './helpers';

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
            await raw(page).getByLabel('Public key', { exact: true }).fill('abcd');
            await raw(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(raw(page).getByText(/expected 32 bytes/i)).toBeVisible();
            await check(page);
        });

        test('verify tab, valid and wrong results', async ({ page }) => {
            await raw(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
            await raw(page).getByRole('group', { name: 'Message format' }).getByRole('button', { name: 'Hex' }).click();
            await raw(page).getByLabel('Message', { exact: true }).fill(RFC.messageHex);
            await raw(page).getByLabel('Signature', { exact: true }).fill(RFC.signature);
            await raw(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(raw(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            await raw(page).getByLabel('Message', { exact: true }).fill('73');
            await raw(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(raw(page).getByText('Signature is wrong')).toBeVisible();
            await check(page);
        });

        test('verify tab, wrong signature with hints', async ({ page }) => {
            // the RFC vector with the message typed as text "r" read as hex: the hint says so
            await raw(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
            await raw(page).getByLabel('Message', { exact: true }).fill('72');
            await raw(page).getByLabel('Signature', { exact: true }).fill(RFC.signature);
            await raw(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(raw(page).getByRole('region', { name: 'Why it may be wrong' })).toBeVisible();
            await check(page);
        });

        test('examples, valid and ZIP215', async ({ page }) => {
            const load = raw(page).getByRole('button', { name: 'Load example' });
            await load.click();
            await expect(raw(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            for (let i = 0; i < 3; i++) await load.click();
            await expect(raw(page).getByText('Only valid under ZIP215.')).toBeVisible();
            await check(page);
        });

        test('sign tab, example with the published signature', async ({ page }) => {
            await page.getByRole('button', { name: 'Create a signature' }).click();
            await raw(page).getByRole('button', { name: 'Load example' }).click();
            await raw(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(raw(page).getByText('Identical to the signature published in RFC 8032.')).toBeVisible();
            await check(page);
        });

        test('key fields with Download and Choose file, and the saved-file reminder', async ({ page }) => {
            await page.getByRole('button', { name: 'Create a signature' }).click();
            await raw(page).getByRole('button', { name: 'Load example' }).click();
            await raw(page).getByRole('button', { name: 'Download private key' }).click();
            await expect(raw(page).getByRole('status')).toBeVisible();
            await check(page);
        });

        test('verify tab, a container pasted in the signature field', async ({ page }) => {
            await raw(page)
                .getByLabel('Signature', { exact: true })
                .fill(
                    'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg',
                );
            await expect(raw(page).getByRole('button', { name: 'Open in Tokens and files' })).toBeVisible();
            await check(page);
        });

        test('signed formats, a token verified', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            await signed(page).getByLabel('Token', { exact: true }).fill(JWS.token);
            await signed(page).getByLabel('Public key', { exact: true }).fill(JWS.jwkPublic);
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByRole('region', { name: 'Token contents' })).toBeVisible();
            await check(page);
        });

        test('signed formats, hints and an example', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            const [header, payload, signature] = JWS.token.split('.');
            const bytes = Buffer.from(signature, 'base64url');
            const swapped = `${header}.${payload}.${Buffer.concat([bytes.subarray(32), bytes.subarray(0, 32)]).toString('base64url')}`;
            await signed(page).getByLabel('Token', { exact: true }).fill(swapped);
            await signed(page).getByLabel('Public key', { exact: true }).fill(JWS.jwkPublic);
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByRole('region', { name: 'Why it may be wrong' })).toBeVisible();
            await check(page);
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await expect(signed(page).getByText(/^Expired: it expired on/)).toBeVisible();
            await check(page);
        });

        test('signed formats, an SSH signature verified, hints and created', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            await panel(page).getByRole('button', { name: 'SSH signature' }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await expect(signed(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            await signed(page).getByLabel('Message', { exact: true }).fill('hello world');
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByRole('region', { name: 'Why it may be wrong' })).toBeVisible();
            await check(page);
            await panel(page).getByRole('button', { name: 'Create a signature' }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await signed(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(signed(page).getByText('Identical to the signature made by ssh-keygen.')).toBeVisible();
            await check(page);
        });

        test('signed formats, a minisign signature verified, hints and created', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            await panel(page).getByRole('button', { name: 'minisign' }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await expect(signed(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            await signed(page).getByLabel('Message', { exact: true }).fill('hello world');
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByRole('region', { name: 'Why it may be wrong' })).toBeVisible();
            await check(page);
            await panel(page).getByRole('button', { name: 'Create a signature' }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await signed(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(signed(page).getByText('Identical to the signature made by minisign.')).toBeVisible();
            await check(page);
        });

        test('signed formats, a signify signature verified, hints and created', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            await panel(page).getByRole('button', { name: 'signify' }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await expect(signed(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            await signed(page).getByLabel('Message', { exact: true }).fill('hello world');
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByRole('region', { name: 'Why it may be wrong' })).toBeVisible();
            await check(page);
            await panel(page).getByRole('button', { name: 'Create a signature' }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await signed(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(signed(page).getByText('Identical to the signature made by signify.')).toBeVisible();
            await check(page);
        });

        test('signed formats, a COSE message verified, hints and created', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            await panel(page).getByRole('button', { name: 'COSE', exact: true }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await expect(signed(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await signed(page).getByLabel('Payload', { exact: true }).fill('hello world\n');
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByRole('region', { name: 'Why it may be wrong' })).toBeVisible();
            await check(page);
            await panel(page).getByRole('button', { name: 'Create a signature' }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await signed(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(signed(page).getByText('Identical to the message of the example.')).toBeVisible();
            await check(page);
        });

        test('signed formats, an OpenPGP signature verified, hints, and the note on creating', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            await panel(page).getByRole('button', { name: 'OpenPGP', exact: true }).click();
            await signed(page).getByRole('button', { name: 'Load example' }).click();
            await expect(signed(page).getByText('Signature is valid')).toBeVisible();
            await check(page);
            await signed(page).getByLabel('Message', { exact: true }).fill('hello world');
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByRole('region', { name: 'Why it may be wrong' })).toBeVisible();
            await check(page);
            await panel(page).getByRole('button', { name: 'Create a signature' }).click();
            await expect(signed(page).getByText(/Creating OpenPGP signatures is not offered here/)).toBeVisible();
            await check(page);
        });

        test('signed formats, a JWK Set: the key picked, and the choice when the token names none', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            for (let i = 0; i < 3; i++) await signed(page).getByRole('button', { name: 'Load example' }).click();
            await expect(signed(page).getByText(/Using the key "key-2" of the set/)).toBeVisible();
            await check(page);
            const [header, payload, signature] = (await signed(page).getByLabel('Token', { exact: true }).inputValue()).split('.');
            const noKid = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
            await signed(page).getByLabel('Token', { exact: true }).fill(`${noKid}.${payload}.${signature}`);
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByRole('button', { name: 'Use the key "key-2"' })).toBeVisible();
            await check(page);
            expect(header).toBeTruthy();
        });

        test('signed formats, a token with an error, and creating one', async ({ page }) => {
            await page.getByRole('tab', { name: 'Tokens and files' }).click();
            await signed(page).getByLabel('Token', { exact: true }).fill('a.b');
            await signed(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(signed(page).getByText(/three parts/)).toBeVisible();
            await check(page);
            await panel(page).getByRole('button', { name: 'Create a signature' }).click();
            await signed(page).getByLabel('Private key', { exact: true }).fill(JWS.privateKeyHex);
            await signed(page).getByLabel('Payload', { exact: true }).fill('{"sub":"ada"}');
            await signed(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(signed(page).locator('.result')).not.toBeEmpty();
            await check(page);
        });

        test('format menu open', async ({ page }) => {
            await raw(page).getByLabel('Public key', { exact: true }).fill(RFC.publicKey);
            await page.getByRole('button', { name: /^Public key format:/ }).click();
            await expect(page.getByRole('menu')).toBeVisible();
            await check(page);
        });

        test('choice between two readings', async ({ page }) => {
            // a 43-character base58 key that is also valid base64
            await raw(page).getByLabel('Public key', { exact: true }).fill('MHMb3k7Hjcn1ZedZZy2CWMJjiRiJrVD9zNm96cPpHke');
            await raw(page).getByRole('button', { name: 'Verify', exact: true }).click();
            await expect(
                raw(page)
                    .getByRole('button', { name: /^Read as/ })
                    .first(),
            ).toBeVisible();
            await check(page);
        });

        test('sign tab, with a result', async ({ page }) => {
            await page.getByRole('button', { name: 'Create a signature' }).click();
            await raw(page).getByRole('button', { name: 'Generate' }).click();
            await raw(page).getByLabel('Message', { exact: true }).fill('accessibility');
            await raw(page).getByRole('button', { name: 'Sign', exact: true }).click();
            await expect(raw(page).locator('.result')).not.toBeEmpty();
            await pickFormat(page, 'Signature format', 'hex');
            await check(page);
        });
    });
}
