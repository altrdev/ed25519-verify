import { fireEvent, screen, within } from '@testing-library/preact';
import type { FieldFormat, RawFormat } from '../enum';
import { formatPreference } from '../store';

/** The format preferences are shared state: every test starts from the same one. */
export function setFormats(format: RawFormat) {
    formatPreference.publicKey.value = format;
    formatPreference.privateKey.value = format;
    formatPreference.signature.value = format;
}

/** The button of a format menu, by the name of the field ("Public key format"). */
export const formatButton = (name: string) => screen.getByRole('button', { name: new RegExp(`^${name}:`) });

/** Opens the menu of a field and picks a format. */
export function pickFormat(name: string, format: FieldFormat) {
    fireEvent.click(formatButton(name));
    const item = within(screen.getByRole('menu', { name }))
        .getAllByRole('menuitemradio')
        .find((el) => el.getAttribute('data-format') === format);
    if (!item) throw new Error(`no ${format} in the menu of ${name}`);
    fireEvent.click(item);
}
