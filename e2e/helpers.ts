import type { ConsoleMessage, Page } from '@playwright/test';

// RFC 8032, section 7.1, TEST 2: a one byte message (0x72)
export const RFC = {
    publicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    privateKey: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    messageHex: '72',
    signature:
        '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
};

/** Everything the page reports as a problem: console errors and warnings, uncaught errors, CSP violations. */
export function collectProblems(page: Page): string[] {
    const problems: string[] = [];
    page.on('console', (message: ConsoleMessage) => {
        if (message.type() === 'error' || message.type() === 'warning') problems.push(`${message.type()}: ${message.text()}`);
    });
    page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`));
    return problems;
}

/** Opens the menu of a field and picks a format (`data-format`). */
export async function pickFormat(page: Page, name: string, format: string) {
    await page.getByRole('button', { name: new RegExp(`^${name}:`) }).click();
    await page.getByRole('menu', { name }).locator(`[data-format="${format}"]`).click();
}

/** The tab that is showing (both forms stay mounted, the other one is hidden). */
export const panel = (page: Page) => page.getByRole('tabpanel');

// RFC 8037, appendix A: the key (it is the one of RFC 8032 test 1) and a JWS made with it
export const JWS = {
    privateKeyHex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    jwkPublic: '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
    token: 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg',
};
