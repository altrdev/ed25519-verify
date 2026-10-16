import type { ComponentChildren } from 'preact';

export default function Banner({ kind, children }: { kind: 'success' | 'error'; children: ComponentChildren }) {
    return (
        <div class={`banner ${kind}`} role="alert">
            <svg viewBox="0 0 24 24" width="24" height="24" aria-hidden="true">
                <path d={kind === 'success' ? mdiCheck : mdiAlert} fill="currentColor" />
            </svg>
            <div>{children}</div>
        </div>
    );
}

// Material Design Icons paths (check, alert)
const mdiCheck = 'M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z';
const mdiAlert = 'M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z';
