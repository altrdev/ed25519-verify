import { inspectInputs } from './diagnose';
import type { Verdict } from './signature';

interface Check {
    label: string;
    /** `skip`: not reached, because a step before it already failed */
    state: 'ok' | 'fail' | 'skip';
    detail?: string;
}

/** The steps a verification goes through, in the order it takes them, and where it stopped. */
export function checksOf(signature: Uint8Array, publicKey: Uint8Array, verdict: Verdict): Check[] {
    const inputs = inspectInputs(publicKey, signature);
    const steps: Check[] = [
        { label: 'Public key is 32 bytes', state: publicKey.length === 32 ? 'ok' : 'fail', detail: `got ${publicKey.length}` },
        { label: 'Signature is 64 bytes', state: signature.length === 64 ? 'ok' : 'fail', detail: `got ${signature.length}` },
        { label: 'Public key is a point of the curve', state: inputs.keyOnCurve ? 'ok' : 'fail' },
        { label: 'R, the first half, is a point of the curve', state: inputs.rOnCurve ? 'ok' : 'fail' },
        { label: 'S, the second half, is reduced (S < L)', state: inputs.sReduced ? 'ok' : 'fail' },
    ];
    const reached = steps.every((step) => step.state === 'ok') || verdict === 'permissive-only';
    steps.push({
        label: 'The equation [S]B = R + [k]A holds',
        state: verdict === 'valid' ? 'ok' : reached ? 'fail' : 'skip',
        detail: verdict === 'permissive-only' ? 'only under ZIP215' : undefined,
    });
    return steps;
}

const MARK = { ok: '✓', fail: '✕', skip: '–' } as const;

/** What was checked, under the verdict. */
export default function Checks({ signature, publicKey, verdict }: { signature: Uint8Array; publicKey: Uint8Array; verdict: Verdict }) {
    return (
        <ul class="checks" aria-label="What was checked">
            {checksOf(signature, publicKey, verdict).map((step) => (
                <li key={step.label} class={step.state}>
                    <i aria-hidden="true">{MARK[step.state]}</i>
                    <span>{step.label}</span>
                    {step.detail && step.state !== 'ok' && <code>{step.detail}</code>}
                    <span class="sr-only">{step.state === 'ok' ? ', passed' : step.state === 'fail' ? ', failed' : ', not reached'}</span>
                </li>
            ))}
        </ul>
    );
}
