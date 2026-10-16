import { useState } from 'preact/hooks';
import JwsPanel from './JwsPanel';
import Segmented from './Segmented';

type SignedFormat = 'jws';
type Mode = 'verify' | 'create';

const FORMATS: { value: SignedFormat; label: string }[] = [{ value: 'jws', label: 'JWS / JWT' }];
const MODES: { value: Mode; label: string }[] = [
    { value: 'verify', label: 'Verify a token' },
    { value: 'create', label: 'Create a token' },
];

/** Signatures in the containers other tools use (a JWT, a minisign file...): the container is read, the signed bytes are worked out. */
export default function FormSigned() {
    const [format, setFormat] = useState<SignedFormat>('jws');
    const [mode, setMode] = useState<Mode>('verify');

    return (
        <section class="card">
            <div class="mode-row">
                <Segmented options={FORMATS} value={format} onChange={setFormat} label="Signature format" />
                <Segmented options={MODES} value={mode} onChange={setMode} label="Action" />
            </div>
            {format === 'jws' && <JwsPanel mode={mode} />}
        </section>
    );
}
