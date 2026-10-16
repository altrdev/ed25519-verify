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

/* ------------------------------------------------------------------------ Signed formats */

export interface SharedToken {
    token: string;
    publicKey: string;
}

/** The fragment of a link to a JWS verification (`#fmt=jws&token=…&key=…`), or '' when there is nothing to share. */
export function jwsShareFragment({ token, publicKey }: SharedToken): string {
    if (!token.trim() && !publicKey.trim()) return '';
    const params = new URLSearchParams({ fmt: 'jws' });
    if (token.trim()) params.set('token', token.trim());
    if (publicKey.trim()) params.set('key', publicKey.trim());
    return `#${params}`;
}

/** What a fragment holds when it is a link to a JWS verification, null for anything else. */
export function parseJwsShare(fragment: string): Partial<SharedToken> | null {
    const params = new URLSearchParams(fragment.replace(/^#/, ''));
    if (params.get('fmt') !== 'jws') return null;
    const token = params.get('token');
    const publicKey = params.get('key');
    return { ...(token !== null && { token }), ...(publicKey !== null && { publicKey }) };
}

export interface SharedSshsig {
    signature: string;
    publicKey: string;
    namespace: string;
    message: string;
    messageFormat: MessageFormat;
}

/** The fragment of a link to an SSH signature verification, or '' when there is nothing to share (a file cannot be in a link). */
export function sshsigShareFragment({ signature, publicKey, namespace, message, messageFormat }: SharedSshsig): string {
    if (!signature.trim() && !publicKey.trim() && !message) return '';
    const params = new URLSearchParams({ fmt: 'sshsig' });
    if (signature.trim()) params.set('sig', signature.trim());
    if (publicKey.trim()) params.set('key', publicKey.trim());
    if (namespace.trim()) params.set('ns', namespace.trim());
    if (message) params.set('msg', message);
    if (message && messageFormat !== MessageFormat.Text) params.set('mf', messageFormat);
    return `#${params}`;
}

export function parseSshsigShare(fragment: string): Partial<SharedSshsig> | null {
    const params = new URLSearchParams(fragment.replace(/^#/, ''));
    if (params.get('fmt') !== 'sshsig') return null;
    const get = (key: string) => params.get(key);
    const format = get('mf');
    return {
        ...(get('sig') !== null && { signature: get('sig') as string }),
        ...(get('key') !== null && { publicKey: get('key') as string }),
        ...(get('ns') !== null && { namespace: get('ns') as string }),
        ...(get('msg') !== null && { message: get('msg') as string }),
        messageFormat: format !== null && MESSAGE_FORMATS.includes(format) ? (format as MessageFormat) : MessageFormat.Text,
    };
}

export interface SharedMinisign {
    signature: string;
    publicKey: string;
    message: string;
    messageFormat: MessageFormat;
}

/** The fragment of a link to a minisign verification, or '' when there is nothing to share (a file cannot be in a link). */
export function minisignShareFragment({ signature, publicKey, message, messageFormat }: SharedMinisign): string {
    if (!signature.trim() && !publicKey.trim() && !message) return '';
    const params = new URLSearchParams({ fmt: 'minisign' });
    if (signature.trim()) params.set('sig', signature.trim());
    if (publicKey.trim()) params.set('key', publicKey.trim());
    if (message) params.set('msg', message);
    if (message && messageFormat !== MessageFormat.Text) params.set('mf', messageFormat);
    return `#${params}`;
}

export function parseMinisignShare(fragment: string): Partial<SharedMinisign> | null {
    const params = new URLSearchParams(fragment.replace(/^#/, ''));
    if (params.get('fmt') !== 'minisign') return null;
    const get = (key: string) => params.get(key);
    const format = get('mf');
    return {
        ...(get('sig') !== null && { signature: get('sig') as string }),
        ...(get('key') !== null && { publicKey: get('key') as string }),
        ...(get('msg') !== null && { message: get('msg') as string }),
        messageFormat: format !== null && MESSAGE_FORMATS.includes(format) ? (format as MessageFormat) : MessageFormat.Text,
    };
}
