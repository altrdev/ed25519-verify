import type { ComponentChildren } from 'preact';
import { useEffect, useRef } from 'preact/hooks';
import { Icon } from './icons';
import { reveal, useVerdictScope } from './Verdict';

/**
 * `stamp`: the verdict itself, set large under a "Verdict" label, as the head of the verdict card (a note or a result is not one).
 * `pill`: the verdict in a word, which the verify form shows beside its Verify button; a click on Verify also brings the banner into view.
 */
export default function Banner({
    kind,
    stamp,
    pill,
    children,
}: {
    kind: 'success' | 'error' | 'warning';
    stamp?: boolean;
    pill?: string;
    children: ComponentChildren;
}) {
    const scope = useVerdictScope();
    const element = useRef<HTMLDivElement>(null);
    const owner = useRef({});

    // after every render: a verification that gives the same answer again still renders, and is still to be brought into view
    useEffect(() => {
        if (!pill) return;
        const shown = scope.pill.peek();
        if (shown?.kind !== kind || shown.label !== pill) scope.pill.value = { kind, label: pill };
        scope.owner.current = owner.current;
        if (scope.armed.current) {
            scope.armed.current = false;
            reveal(element.current);
        }
    });
    // only the banner that published the pill takes it back: the next verdict may already have replaced it
    useEffect(
        () => () => {
            if (scope.owner.current !== owner.current) return;
            scope.pill.value = null;
            scope.owner.current = null;
        },
        [scope],
    );

    return (
        <div class={`banner ${kind}${stamp ? ' stamp' : ''}`} role="alert" ref={element}>
            <Icon name={kind === 'success' ? 'check' : 'alert'} size={22} />
            <div class="banner-body">{children}</div>
        </div>
    );
}
