/**
 * Share links: what the Verify tab holds, in the fragment of the URL (`#pk=…&msg=…&mf=text&sig=…`). The fragment is never sent
 * to a server (not even the one that hosts the page), so a link carries the data without anyone but the reader seeing it.
 * Only public things are shared: a private key never goes in a link.
 */
import { MessageFormat } from './enum';

export interface SharedVerification {
    publicKey: string;
    message: string;
    messageFormat: MessageFormat;
    signature: string;
}

const MESSAGE_FORMATS = Object.values(MessageFormat) as string[];

/** The fragment (with the `#`) for a verification, or '' when there is nothing to share. */
export function shareFragment({ publicKey, message, messageFormat, signature }: SharedVerification): string {
    if (!publicKey.trim() && !message && !signature.trim()) return '';
    const params = new URLSearchParams();
    if (publicKey.trim()) params.set('pk', publicKey.trim());
    if (message) params.set('msg', message);
    if (message && messageFormat !== MessageFormat.Text) params.set('mf', messageFormat);
    if (signature.trim()) params.set('sig', signature.trim());
    return `#${params}`;
}

/** What a fragment holds, or null when it is not a share link (so any other `#` is left alone). */
export function parseShareFragment(fragment: string): Partial<SharedVerification> | null {
    const params = new URLSearchParams(fragment.replace(/^#/, ''));
    const publicKey = params.get('pk');
    const message = params.get('msg');
    const signature = params.get('sig');
    if (publicKey === null && message === null && signature === null) return null;
    const format = params.get('mf');
    return {
        ...(publicKey !== null && { publicKey }),
        ...(message !== null && { message }),
        ...(signature !== null && { signature }),
        messageFormat: format !== null && MESSAGE_FORMATS.includes(format) ? (format as MessageFormat) : MessageFormat.Text,
    };
}
