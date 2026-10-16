import type { ComponentChildren } from 'preact';
import { useId, useState } from 'preact/hooks';
import CopyButton from './CopyButton';
import { Icon } from './icons';

interface FieldProps {
    label: string;
    value: string;
    rows?: number;
    /** grow with the number of lines (up to 8), so a pasted multi-line value such as a PEM is visible */
    growWithContent?: boolean;
    disabled?: boolean;
    placeholder?: string;
    /** validation message, shown under the field */
    error?: string;
    /** neutral note under the field (hidden while there is an error) */
    hint?: string;
    /** extra buttons on the label row */
    actions?: ComponentChildren;
    /** copy button on the label row */
    copyable?: boolean;
    /** hide the content (like a password) with a show/hide toggle */
    secret?: boolean;
    /** controlled visibility of a secret field; uncontrolled when omitted */
    revealed?: boolean;
    onRevealedChange?: (revealed: boolean) => void;
    onInput?: (value: string) => void;
    onChange?: (value: string) => void;
}

export default function Field({
    label, value, rows = 3, growWithContent, disabled, placeholder, error, hint, actions, copyable, secret,
    revealed: revealedProp, onRevealedChange, onInput, onChange,
}: FieldProps) {
    const id = useId();
    const errorId = `${id}-error`;
    const [revealedState, setRevealedState] = useState(false);
    const revealed = revealedProp ?? revealedState;
    const masked = secret && !revealed;
    const lineCount = value.replace(/\n+$/, '').split('\n').length;
    const visibleRows = growWithContent ? Math.min(Math.max(rows, lineCount), 8) : rows;

    const toggleReveal = () => {
        setRevealedState(!revealed);
        onRevealedChange?.(!revealed);
    };

    return (
        <div class={`field${error ? ' invalid' : ''}`}>
            <div class="field-head">
                <label for={id}>{label}</label>
                <div class="field-actions">
                    {actions}
                    {secret && (
                        <button
                            type="button"
                            class="chip"
                            aria-label={`${revealed ? 'Hide' : 'Show'} ${label.toLowerCase()}`}
                            aria-pressed={revealed}
                            onClick={toggleReveal}
                        >
                            <Icon name={revealed ? 'eyeOff' : 'eye'} size={16} />
                            {revealed ? 'Hide' : 'Show'}
                        </button>
                    )}
                    {copyable && <CopyButton text={value} label={`Copy ${label.toLowerCase()}`} />}
                </div>
            </div>
            <textarea
                id={id}
                class={masked ? 'masked' : ''}
                rows={visibleRows}
                value={value}
                disabled={disabled}
                placeholder={placeholder}
                spellcheck={false}
                autocomplete="off"
                autocapitalize="off"
                aria-invalid={error ? true : undefined}
                aria-describedby={error ? errorId : undefined}
                onInput={(e) => onInput?.(e.currentTarget.value)}
                onChange={(e) => onChange?.(e.currentTarget.value)}
            />
            {error && <p class="field-error" id={errorId} role="alert">{error}</p>}
            {hint && !error && <p class="field-hint">{hint}</p>}
        </div>
    );
}
