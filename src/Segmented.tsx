interface SegmentedProps<T extends string> {
    options: { value: T; label: string }[];
    value: T;
    onChange: (value: T) => void;
    /** accessible name of the group, when no visible label is associated through labelledBy */
    label?: string;
    labelledBy?: string;
}

/** Compact toggle group where exactly one option is active. */
export default function Segmented<T extends string>({ options, value, onChange, label, labelledBy }: SegmentedProps<T>) {
    return (
        // biome-ignore lint/a11y/useSemanticElements: a fieldset brings its own border and layout, this is a styled toggle group
        <div class="segmented small" role="group" aria-label={label} aria-labelledby={labelledBy}>
            {options.map((option) => (
                <button
                    type="button"
                    key={option.value}
                    class={value === option.value ? 'active' : ''}
                    aria-pressed={value === option.value}
                    onClick={() => onChange(option.value)}
                >
                    {option.label}
                </button>
            ))}
        </div>
    );
}
