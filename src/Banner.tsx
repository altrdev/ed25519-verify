import type { ComponentChildren } from 'preact';
import { Icon } from './icons';

export default function Banner({ kind, children }: { kind: 'success' | 'error' | 'warning'; children: ComponentChildren }) {
    return (
        <div class={`banner ${kind}`} role="alert">
            <Icon name={kind === 'success' ? 'check' : 'alert'} size={22} />
            <div class="banner-body">{children}</div>
        </div>
    );
}
