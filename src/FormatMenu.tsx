import { useEffect, useId, useRef, useState } from 'preact/hooks';
import { CODECS } from './codecs';
import type { FieldFormat, RawFormat } from './enum';
import { ECOSYSTEM_FORMATS, ECOSYSTEM_KINDS } from './ecosystems';
import { FILE_FORMATS, keyFileOf, KEY_FILE_LABELS, labelOf } from './keyfiles';
import { Icon } from './icons';
import type { FieldReading } from './signature';

const ORDER: RawFormat[] = ['hex', 'hex0x', 'base64', 'base64url', 'base58', 'base32', 'bytes'];
const EXAMPLES: Record<RawFormat, string> = {
    hex: '00ff10…',
    hex0x: '0x00ff10…',
    base64: 'AP8Q…',
    base64url: 'AP8Q',
    base58: '1Zz…',
    base32: 'AD7RA…',
    bytes: '[0, 255, 16…]',
};

const KEY_FILE_EXAMPLES: Record<'public' | 'private', Partial<Record<FieldFormat, string>>> = {
    public: {
        pem: 'BEGIN PUBLIC KEY', openssh: 'ssh-ed25519 AAAA…', jwk: '{"kty":"OKP","x"…}',
        didkey: 'did:key:z6Mk…', stellar: 'G…', onion: 'xxxx….onion', near: 'ed25519:…',
    },
    private: {
        pem: 'BEGIN PRIVATE KEY', openssh: 'BEGIN OPENSSH PRIVATE KEY', jwk: '{"kty":"OKP","d"…}',
        stellar: 'S…', near: 'ed25519:… (64 bytes)', solana: '[12, 34… 64 numbers]',
    },
};

/** Short name of what a field holds, for the button: "Base58", "PEM"... */
export const readingLabel = (reading: FieldReading, kind?: Props['kind']): string => labelOf(readingFormat(reading, kind));

/** The item of the menu that matches what a field holds (a list of 64 numbers in a private key field is a Solana keypair file). */
export const readingFormat = (reading: FieldReading, kind?: Props['kind']): FieldFormat => {
    if (reading.structured) return keyFileOf(reading.structured);
    return kind === 'private' && reading.format === 'bytes' && reading.bytes.length === 64 ? 'solana' : reading.format!;
};

/** The line under a field once its text is recognised: "Detected: base58 · 32 bytes". */
export function readingHint(reading: FieldReading | null): string | undefined {
    if (!reading) return undefined;
    return reading.structured
        ? `Detected format: ${reading.structured}`
        : `Detected: ${CODECS[reading.format!].label.toLowerCase()} · ${reading.bytes.length} bytes`;
}

interface Props {
    /** what the button shows, e.g. "Base58"; "Auto" when there is nothing to detect */
    label: string;
    /** the format to tick in the list */
    current: FieldFormat | null;
    /** what the field holds: a key can be written as a key file too, a signature cannot */
    kind: 'public' | 'private' | 'signature';
    /** accessible name, e.g. "Public key format" */
    name: string;
    disabled?: boolean;
    onSelect: (format: FieldFormat) => void;
}

/** The format of a field. Picking one rewrites the text (an input) or changes how the result is written (an output). */
export default function FormatMenu({ label, current, kind, name, disabled, onSelect }: Props) {
    const [open, setOpen] = useState(false);
    const root = useRef<HTMLDivElement>(null);
    const menuId = useId();

    const items = () => Array.from(root.current?.querySelectorAll<HTMLButtonElement>('[role="menuitemradio"]') ?? []);
    const close = (refocus = false) => {
        setOpen(false);
        if (refocus) root.current?.querySelector<HTMLButtonElement>('button[aria-haspopup]')?.focus();
    };

    // the field can stop being valid while the menu is open: there is nothing to pick for any more
    useEffect(() => {
        if (disabled) setOpen(false);
    }, [disabled]);

    useEffect(() => {
        if (!open) return;
        const all = items();
        (all.find((item) => item.getAttribute('aria-checked') === 'true') ?? all[0])?.focus();
        const onPointerDown = (event: MouseEvent) => {
            if (!root.current?.contains(event.target as Node)) setOpen(false);
        };
        document.addEventListener('mousedown', onPointerDown);
        return () => document.removeEventListener('mousedown', onPointerDown);
    }, [open]);

    const item = (format: FieldFormat, text: string, example: string) => (
        <button
            type="button"
            role="menuitemradio"
            aria-checked={format === current}
            class={format === current ? 'current' : ''}
            key={format}
            data-format={format}
            onClick={() => {
                close(true);
                onSelect(format);
            }}
        >
            <span>{text} <small>{example}</small></span>
            {format === current && <Icon name="check" size={16} />}
        </button>
    );

    const onMenuKeyDown = (event: KeyboardEvent) => {
        const all = items();
        const index = all.indexOf(document.activeElement as HTMLButtonElement);
        const move = (to: number) => {
            event.preventDefault();
            all[(to + all.length) % all.length]?.focus();
        };
        if (event.key === 'Escape') {
            event.preventDefault();
            close(true);
        } else if (event.key === 'ArrowDown') move(index + 1);
        else if (event.key === 'ArrowUp') move(index - 1);
        else if (event.key === 'Home') move(0);
        else if (event.key === 'End') move(all.length - 1);
        else if (event.key === 'Tab') setOpen(false);
    };

    return (
        <div class="menu-wrap" ref={root}>
            <button
                type="button"
                class="chip format"
                aria-label={`${name}: ${label}`}
                aria-haspopup="menu"
                aria-expanded={open}
                aria-controls={open ? menuId : undefined}
                disabled={disabled}
                onClick={() => !disabled && setOpen(!open)}
            >
                {label}
                <Icon name="chevron" size={14} />
            </button>
            {open && (
                <div class="menu" id={menuId} role="menu" aria-label={name} onKeyDown={onMenuKeyDown}>
                    <h4 role="presentation">Encodings</h4>
                    {ORDER.map((format) => item(format, CODECS[format].label, EXAMPLES[format]))}
                    {kind !== 'signature' && (
                        <>
                            <hr role="separator" />
                            <h4 role="presentation">Key files</h4>
                            {FILE_FORMATS.map((format) => item(format, KEY_FILE_LABELS[format], KEY_FILE_EXAMPLES[kind][format] ?? ''))}
                            <hr role="separator" />
                            <h4 role="presentation">Ecosystems</h4>
                            {ECOSYSTEM_FORMATS.filter((format) => ECOSYSTEM_KINDS[format][kind]).map((format) =>
                                item(format, KEY_FILE_LABELS[format], KEY_FILE_EXAMPLES[kind][format] ?? ''))}
                        </>
                    )}
                </div>
            )}
        </div>
    );
}
