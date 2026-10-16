import { useState } from 'preact/hooks';
import FormSign from './FormSign';
import FormVerify from './FormVerify';
import Segmented from './Segmented';

type Mode = 'verify' | 'create';

const MODES: { value: Mode; label: string }[] = [
    { value: 'verify', label: 'Verify a signature' },
    { value: 'create', label: 'Create a signature' },
];

type VerifyProps = Parameters<typeof FormVerify>[0];

/** The raw Ed25519 signature: a public key, a message and 64 bytes. Verify and create share the tab, as in "Tokens and files". */
export default function FormRaw(props: VerifyProps) {
    const [mode, setMode] = useState<Mode>('verify');
    const header = (
        <div class="mode-row">
            <Segmented options={MODES} value={mode} onChange={setMode} label="Action" />
        </div>
    );
    return (
        <>
            {/* both forms stay mounted, so what was typed is not lost when switching */}
            <div class="panel" hidden={mode !== 'verify'}>
                <FormVerify {...props} header={header} />
            </div>
            <div class="panel" hidden={mode !== 'create'}>
                <FormSign header={header} />
            </div>
        </>
    );
}
