import { useState } from 'preact/hooks';
import JwsPanel from './JwsPanel';
import Segmented from './Segmented';
import type { SharedSshsig, SharedToken } from './share';
import SshsigPanel from './SshsigPanel';

type SignedFormat = 'jws' | 'sshsig';
type Mode = 'verify' | 'create';

const FORMATS: { value: SignedFormat; label: string }[] = [
    { value: 'jws', label: 'JWS / JWT' },
    { value: 'sshsig', label: 'SSH signature' },
];
const MODES: { value: Mode; label: string }[] = [
    { value: 'verify', label: 'Verify a signature' },
    { value: 'create', label: 'Create a signature' },
];

interface Props {
    /** a link to a verification: which format it is for, and what it holds */
    sharedJws?: Partial<SharedToken> | null;
    sharedSshsig?: Partial<SharedSshsig> | null;
}

/** Signatures in the containers other tools use (a JWT, an SSH signature...): the container is read, the signed bytes are worked out. */
export default function FormSigned({ sharedJws, sharedSshsig }: Props) {
    const [format, setFormat] = useState<SignedFormat>(sharedSshsig ? 'sshsig' : 'jws');
    const [mode, setMode] = useState<Mode>('verify');

    return (
        <section class="card">
            <div class="mode-row">
                <Segmented options={FORMATS} value={format} onChange={setFormat} label="Signature format" />
                <Segmented options={MODES} value={mode} onChange={setMode} label="Action" />
            </div>
            {/* both formats stay mounted, so what was typed is not lost when switching */}
            <div class="panel" hidden={format !== 'jws'}>
                <JwsPanel mode={mode} initial={sharedJws ?? undefined} autoVerify={!!sharedJws?.token && !!sharedJws?.publicKey} />
            </div>
            <div class="panel" hidden={format !== 'sshsig'}>
                <SshsigPanel mode={mode} initial={sharedSshsig ?? undefined} autoVerify={!!sharedSshsig?.signature} />
            </div>
        </section>
    );
}
