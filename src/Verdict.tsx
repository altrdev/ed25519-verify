import { type Signal, signal } from '@preact/signals';
import { type ComponentChildren, createContext } from 'preact';
import { useContext, useMemo } from 'preact/hooks';
import { Icon } from './icons';

export interface Pill {
    kind: 'success' | 'warning' | 'error';
    label: string;
}

/** What a verify form shares with its own parts: the short verdict for the pill, who published it, and whether a click asked to see it. */
interface Scope {
    pill: Signal<Pill | null>;
    owner: { current: object | null };
    armed: { current: boolean };
}

const outside: Scope = { pill: signal(null), owner: { current: null }, armed: { current: false } };
const Context = createContext<Scope>(outside);

/** Around a verify form: its banner publishes the verdict here, and the pill beside the Verify button shows it. */
export function VerdictScope({ children }: { children: ComponentChildren }) {
    const scope = useMemo<Scope>(() => ({ pill: signal(null), owner: { current: null }, armed: { current: false } }), []);
    return <Context.Provider value={scope}>{children}</Context.Provider>;
}

export const useVerdictScope = () => useContext(Context);

/** The Verify button: besides verifying, it asks for the verdict to be brought into view once it is shown. */
export function VerifyButton({ onClick }: { onClick: () => void }) {
    const scope = useVerdictScope();
    return (
        <button
            type="button"
            class="primary"
            onClick={() => {
                scope.armed.current = true;
                onClick();
            }}
        >
            Verify
        </button>
    );
}

/** The verdict in a word, next to the button that asked for it. The banner under the form is what is announced: this one is for the eye. */
export function VerdictPill() {
    const pill = useVerdictScope().pill.value;
    if (!pill) return null;
    return (
        <span class={`pill ${pill.kind}`} aria-hidden="true">
            <Icon name={pill.kind === 'success' ? 'check' : 'alert'} size={16} />
            {pill.label}
        </span>
    );
}

/** Scrolls to the verdict when it is not in view, gently unless the system asks for less movement. */
export function reveal(element: HTMLElement | null) {
    if (!element?.scrollIntoView) return;
    const { top, bottom } = element.getBoundingClientRect();
    // the top bar floats over the first 80px or so
    if (top >= 90 && bottom <= window.innerHeight) return;
    const calm = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    element.scrollIntoView({ block: 'center', behavior: calm ? 'auto' : 'smooth' });
}
