import type { ComponentChildren } from 'preact';
import { Icon } from './icons';

/** `stamp`: the verdict itself, set large under a "Verdict" label, as the head of the verdict card (a note or a result is not one). */
export default function Banner({
    kind,
    stamp,
    children,
}: {
    kind: 'success' | 'error' | 'warning';
    stamp?: boolean;
    children: ComponentChildren;
}) {
    return (
        <div class={`banner ${kind}${stamp ? ' stamp' : ''}`} role="alert">
            <Icon name={kind === 'success' ? 'check' : 'alert'} size={22} />
            <div class="banner-body">{children}</div>
        </div>
    );
}
