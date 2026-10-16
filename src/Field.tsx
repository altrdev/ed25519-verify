import { useId } from 'preact/hooks';

interface FieldProps {
    label: string;
    value: string;
    rows?: number;
    disabled?: boolean;
    placeholder?: string;
    onInput?: (value: string) => void;
    onChange?: (value: string) => void;
}

export default function Field({ label, value, rows = 3, disabled, placeholder, onInput, onChange }: FieldProps) {
    const id = useId();
    return (
        <div class="field">
            <label for={id}>{label}</label>
            <textarea
                id={id}
                rows={rows}
                value={value}
                disabled={disabled}
                placeholder={placeholder}
                spellcheck={false}
                autocomplete="off"
                onInput={(e) => onInput?.(e.currentTarget.value)}
                onChange={(e) => onChange?.(e.currentTarget.value)}
            />
        </div>
    );
}
