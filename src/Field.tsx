import { useId, useState } from 'preact/hooks';
import CopyButton from './CopyButton';
import { Icon } from './icons';

interface FieldProps {
    label: string;
    value: string;
    rows?: number;
    disabled?: boolean;
    placeholder?: string;
    /** copy button on the label row */
    copyable?: boolean;
    /** hide the content (like a password) with a show/hide toggle */
    secret?: boolean;
    onInput?: (value: string) => void;
    onChange?: (value: string) => void;
}

export default function Field({
    label, value, rows = 3, disabled, placeholder, copyable, secret, onInput, onChange,
}: FieldProps) {
    const id = useId();
    const [revealed, setRevealed] = useState(false);
    const masked = secret && !revealed;

    return (
        <div class="field">
            <div class="field-head">
                <label for={id}>{label}</label>
                <div class="field-actions">
                    {secret && (
                        <button
                            type="button"
                            class="chip"
                            aria-label={`${revealed ? 'Hide' : 'Show'} ${label.toLowerCase()}`}
                            aria-pressed={revealed}
                            onClick={() => setRevealed(!revealed)}
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
                rows={rows}
                value={value}
                disabled={disabled}
                placeholder={placeholder}
                spellcheck={false}
                autocomplete="off"
                autocapitalize="off"
                onInput={(e) => onInput?.(e.currentTarget.value)}
                onChange={(e) => onChange?.(e.currentTarget.value)}
            />
        </div>
    );
}
