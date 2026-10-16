import { spawnSync } from 'node:child_process';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { chmodSync, readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import { collectProblems, JWS, panel, pickFormat, RFC } from './helpers';

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

    test('loads the examples: RFC vectors are valid, the ZIP215 one shows the warning', async ({ page }) => {
        await page.goto('/');
        const load = panel(page).getByRole('button', { name: 'Load example' });
        for (const title of ['RFC 8032 test 1.', 'RFC 8032 test 2.', 'RFC 8032 test 3.']) {
            await load.click();
            await expect(panel(page).getByText(title)).toBeVisible();
            await expect(panel(page).getByText('Signature is valid')).toBeVisible();
        }
        await load.click();
        await expect(panel(page).getByText('Only valid under ZIP215.')).toBeVisible();
        await expect(panel(page).getByText(/not valid under the strict RFC 8032 rules/)).toBeVisible();
    });

    test('the Sign tab reproduces the published signature of a vector', async ({ page }) => {
        await page.goto('/');
        await page.getByRole('tab', { name: 'Sign message' }).click();
        await panel(page).getByRole('button', { name: 'Load example' }).click();
        await panel(page).getByRole('button', { name: 'Sign', exact: true }).click();
        await expect(panel(page).getByText('Identical to the signature published in RFC 8032.')).toBeVisible();
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

test.describe('key files', () => {
    const hasSshKeygen = spawnSync('ssh-keygen', ['-?']).error === undefined;

    test('saves a public key as id_ed25519.pub and opens it again', async ({ page }) => {
        const problems = collectProblems(page);
        await page.goto('/');
        const field = panel(page).getByLabel('Public key', { exact: true });
        await field.fill(RFC.publicKey);
        await pickFormat(page, 'Public key format', 'openssh');
        const text = await field.inputValue();

        const download = page.waitForEvent('download');
        await panel(page).getByRole('button', { name: 'Download public key' }).click();
        const saved = await download;
        expect(saved.suggestedFilename()).toBe('id_ed25519.pub');
        const content = readFileSync((await saved.path()) as string, 'utf8');
        expect(content).toBe(`${text}\n`);

        // the saved file opens in the field and is read as the same key
        await field.fill('');
        await panel(page)
            .getByLabel('File for public key', { exact: true })
            .setInputFiles((await saved.path()) as string);
        await expect(field).toHaveValue(`${text}\n`);
        await expect(panel(page).getByText('Detected format: OpenSSH public key')).toBeVisible();
        expect(problems).toEqual([]); // the download is not blocked by the Content-Security-Policy
    });

    test('a private key saved as id_ed25519 is accepted by ssh-keygen', async ({ page }) => {
        test.skip(!hasSshKeygen, 'ssh-keygen is not installed');
        await page.goto('/');
        await page.getByRole('tab', { name: 'Sign message' }).click();
        await panel(page).getByLabel('Private key', { exact: true }).fill(RFC.privateKey);
        await pickFormat(page, 'Private key format', 'openssh');
        await expect(panel(page).getByLabel('Private key', { exact: true })).toHaveValue(/BEGIN OPENSSH PRIVATE KEY/);

        const download = page.waitForEvent('download');
        await panel(page).getByRole('button', { name: 'Download private key' }).click();
        const saved = await download;
        expect(saved.suggestedFilename()).toBe('id_ed25519');
        await expect(panel(page).getByRole('status')).toContainText('not encrypted');

        const path = (await saved.path()) as string;
        chmodSync(path, 0o600);
        const derived = spawnSync('ssh-keygen', ['-y', '-f', path], { encoding: 'utf8' });
        expect(derived.status, derived.stderr).toBe(0);
        // the public key ssh-keygen derives is the one of the vector
        await pickFormat(page, 'Public key format', 'openssh');
        const shown = await panel(page).getByRole('textbox', { name: 'Deduced Public key' }).inputValue();
        expect(derived.stdout.trim().split(' ').slice(0, 2).join(' ')).toBe(shown.trim());
    });
});

test.describe('signed formats: JWS / JWT', () => {
    test('verifies the token of RFC 8037 and shows what it contains', async ({ page }) => {
        const problems = collectProblems(page);
        await page.goto('/');
        await page.getByRole('tab', { name: 'Signed formats' }).click();
        await panel(page).getByLabel('Token', { exact: true }).fill(JWS.token);
        await panel(page).getByLabel('Public key', { exact: true }).fill(JWS.jwkPublic);
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText('Signature is valid')).toBeVisible();
        await expect(panel(page).getByRole('region', { name: 'Token contents' })).toContainText('Example of Ed25519 signing');
        expect(problems).toEqual([]);
    });

    test('refuses an unsigned token instead of calling it valid', async ({ page }) => {
        await page.goto('/');
        await page.getByRole('tab', { name: 'Signed formats' }).click();
        await panel(page).getByLabel('Token', { exact: true }).fill('eyJhbGciOiJub25lIn0.e30.');
        await panel(page).getByLabel('Public key', { exact: true }).fill(JWS.jwkPublic);
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText(/not signed at all/)).toBeVisible();
        await expect(panel(page).getByText('Signature is valid')).toHaveCount(0);
    });

    test('a token made here is verified by Node crypto, which knows nothing about this code', async ({ page }) => {
        await page.goto('/');
        await page.getByRole('tab', { name: 'Signed formats' }).click();
        await panel(page).getByRole('button', { name: 'Create a token' }).click();
        await panel(page).getByLabel('Private key', { exact: true }).fill(JWS.privateKeyHex);
        await panel(page).getByLabel('Payload', { exact: true }).fill('{"sub":"ada","name":"Zoë"}');
        await panel(page).getByRole('button', { name: 'Sign', exact: true }).click();
        const token = (await panel(page).locator('.result').innerText()).trim();
        expect(token.split('.')).toHaveLength(3);

        const [header, payload, signature] = token.split('.');
        const jwk = JSON.parse(
            await panel(page)
                .getByRole('textbox', { name: /Public key to verify it/ })
                .inputValue(),
        );
        const key = createPublicKey({ key: jwk, format: 'jwk' });
        expect(nodeVerify(null, Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, 'base64url'))).toBe(true);
        expect(JSON.parse(Buffer.from(header, 'base64url').toString())).toEqual({ alg: 'EdDSA', typ: 'JWT' });
    });

    test('suggests what may be wrong with a token, and following it makes it valid', async ({ page }) => {
        await page.goto('/');
        await page.getByRole('tab', { name: 'Signed formats' }).click();
        // the signature of RFC 8037 with its two halves swapped
        const [header, payload, signature] = JWS.token.split('.');
        const bytes = Buffer.from(signature, 'base64url');
        const swapped = `${header}.${payload}.${Buffer.concat([bytes.subarray(32), bytes.subarray(0, 32)]).toString('base64url')}`;
        await panel(page).getByLabel('Token', { exact: true }).fill(swapped);
        await panel(page).getByLabel('Public key', { exact: true }).fill(JWS.jwkPublic);
        await panel(page).getByRole('button', { name: 'Verify', exact: true }).click();
        await expect(panel(page).getByText('Signature is wrong')).toBeVisible();
        await expect(panel(page).getByText('It is valid with the two halves of the signature (R and S) swapped.')).toBeVisible();
    });

    test('loads the examples, and a copied link opens the same verification elsewhere', async ({ page, context }) => {
        await page.goto('/');
        await page.getByRole('tab', { name: 'Signed formats' }).click();
        await panel(page).getByRole('button', { name: 'Load example' }).click();
        await expect(panel(page).getByText('Signature is valid')).toBeVisible();
        await expect(panel(page).getByText('RFC 8037 appendix A.4.')).toBeVisible();
        await panel(page).getByRole('button', { name: 'Load example' }).click();
        await expect(panel(page).getByText(/^Expired: it expired on/)).toBeVisible();

        await panel(page).getByRole('button', { name: 'Copy link to this verification' }).click();
        const link = await page.evaluate(() => navigator.clipboard.readText());
        expect(link).toContain('fmt=jws');
        const other = await context.newPage();
        await other.goto(link);
        // the link opens the tab of the signed formats, filled in and verified
        await expect(panel(other).getByLabel('Token', { exact: true })).toHaveValue(/^eyJ/);
        await expect(panel(other).getByText('Signature is valid')).toBeVisible();
    });

    test('the Create tab reproduces the token of the RFC', async ({ page }) => {
        await page.goto('/');
        await page.getByRole('tab', { name: 'Signed formats' }).click();
        await panel(page).getByRole('button', { name: 'Create a token' }).click();
        await panel(page).getByRole('button', { name: 'Load example' }).click();
        await panel(page).getByRole('button', { name: 'Sign', exact: true }).click();
        await expect(panel(page).getByText('Identical to the token of the example.')).toBeVisible();
        await expect(panel(page).locator('.result')).toHaveText(JWS.token);
    });
});
