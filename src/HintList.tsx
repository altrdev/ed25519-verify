import type { Hints } from './diagnose';

/** Under the "Signature is wrong" banner: what is certain about the inputs, and the retries that make the signature valid. */
export default function HintList({ hints }: { hints: Hints }) {
    if (hints.facts.length === 0 && hints.fixes.length === 0) return null;
    return (
        <section class="hints" aria-label="Why it may be wrong">
            {hints.fixes.length > 0 && (
                <>
                    <h2>The signature is valid if you change something</h2>
                    <ul>
                        {hints.fixes.map((fix) => (
                            <li key={fix}>{fix}</li>
                        ))}
                    </ul>
                </>
            )}
            {hints.facts.length > 0 && (
                <>
                    <h2>Known problems</h2>
                    <ul>
                        {hints.facts.map((fact) => (
                            <li key={fact}>{fact}</li>
                        ))}
                    </ul>
                </>
            )}
        </section>
    );
}
