import type { ComponentChildren } from 'preact';

/** The verdict card under the form: the example note, the verdict, what was checked and what was read from the input. Empty, it is not shown. */
export default function Results({ children }: { children: ComponentChildren }) {
    return <div class="results">{children}</div>;
}
