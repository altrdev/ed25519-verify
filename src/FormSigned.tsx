import { useState } from 'preact/hooks';
import CosePanel from './CosePanel';
import JwsPanel from './JwsPanel';
import MinisignPanel from './MinisignPanel';
import Segmented from './Segmented';
import type { SharedCose, SharedMinisign, SharedSshsig, SharedToken } from './share';
import SshsigPanel from './SshsigPanel';

type SignedFormat = 'jws' | 'sshsig' | 'minisign' | 'cose';
type Mode = 'verify' | 'create';

const FORMATS: { value: SignedFormat; label: string }[] = [
    { value: 'jws', label: 'JWS / JWT' },
    { value: 'sshsig', label: 'SSH signature' },
    { value: 'minisign', label: 'minisign' },
    { value: 'cose', label: 'COSE' },
];
const MODES: { value: Mode; label: string }[] = [
    { value: 'verify', label: 'Verify a signature' },
    { value: 'create', label: 'Create a signature' },
];

interface Props {
    /** a link to a verification: which format it is for, and what it holds */
    sharedJws?: Partial<SharedToken> | null;
    sharedSshsig?: Partial<SharedSshsig> | null;
    sharedMinisign?: Partial<SharedMinisign> | null;
    sharedCose?: Partial<SharedCose> | null;
}

/** Signatures in the containers other tools use (a JWT, an SSH signature...): the container is read, the signed bytes are worked out. */
export default function FormSigned({ sharedJws, sharedSshsig, sharedMinisign, sharedCose }: Props) {
    const [format, setFormat] = useState<SignedFormat>(sharedCose ? 'cose' : sharedMinisign ? 'minisign' : sharedSshsig ? 'sshsig' : 'jws');
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
            <div class="panel" hidden={format !== 'minisign'}>
                <MinisignPanel mode={mode} initial={sharedMinisign ?? undefined} autoVerify={!!sharedMinisign?.signature} />
            </div>
            <div class="panel" hidden={format !== 'cose'}>
                <CosePanel mode={mode} initial={sharedCose ?? undefined} autoVerify={!!sharedCose?.message} />
            </div>
        </section>
    );
}
