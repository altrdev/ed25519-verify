import type { ExampleInfo } from './examples';
import { Icon } from './icons';
import { useVerdictScope } from './Verdict';

/** "Load example": each click asks for the next example of the list. */
export function ExampleButton({ onClick }: { onClick: () => void }) {
    const scope = useVerdictScope();
    return (
        <button
            type="button"
            class="chip"
            onClick={() => {
                scope.armed.current = true; // the example shows its verdict at once, which is brought into view
                onClick();
            }}
        >
            <Icon name="plus" size={16} />
            Load example
        </button>
    );
}

/** Which example is loaded and where it comes from. */
export function ExampleNote({ example }: { example: ExampleInfo | null }) {
    if (!example) return null;
    return (
        <p class="example-note">
            <strong>{example.title}.</strong> {example.note}{' '}
            <a href={example.source} target="_blank" rel="noopener noreferrer">
                Source
            </a>
        </p>
    );
}

/** The index of the example after `current` (the first one when none is loaded yet), going round the list. */
export const nextIndex = (current: number | null, length: number) => (current === null ? 0 : (current + 1) % length);
