import { useState } from 'preact/hooks';
import CosePanel from './CosePanel';
import JwsPanel from './JwsPanel';
import MinisignPanel from './MinisignPanel';
import type { MessageFile } from './messagefile';
import PgpPanel from './PgpPanel';
import Segmented from './Segmented';
import type { SharedCose, SharedMinisign, SharedPgp, SharedSignify, SharedSshsig, SharedToken } from './share';
import SignifyPanel from './SignifyPanel';
import SshsigPanel from './SshsigPanel';

export type SignedFormat = 'jws' | 'sshsig' | 'minisign' | 'signify' | 'cose' | 'pgp';
type Mode = 'verify' | 'create';

const MODES: { value: Mode; label: string }[] = [
    { value: 'verify', label: 'Verify a signature' },
    { value: 'create', label: 'Create a signature' },
];

interface Props {
    /** the format the rail has chosen */
    format: SignedFormat;
    /** a link to a verification: which format it is for, and what it holds */
    sharedJws?: Partial<SharedToken> | null;
    sharedSshsig?: Partial<SharedSshsig> | null;
    sharedMinisign?: Partial<SharedMinisign> | null;
    sharedSignify?: Partial<SharedSignify> | null;
    sharedCose?: Partial<SharedCose> | null;
    sharedPgp?: Partial<SharedPgp> | null;
    /** a file chosen as the message in the Verify tab, carried over with the rest */
    initialFile?: MessageFile | null;
}

/** Signatures in the containers other tools use (a JWT, an SSH signature...): the container is read, the signed bytes are worked out. */
export default function FormSigned({
    format,
    sharedJws,
    sharedSshsig,
    sharedMinisign,
    sharedSignify,
    sharedCose,
    sharedPgp,
    initialFile,
}: Props) {
    const [mode, setMode] = useState<Mode>('verify');

    return (
        <section class="card">
            <div class="mode-row">
                <Segmented options={MODES} value={mode} onChange={setMode} label="Action" />
            </div>
            {/* both formats stay mounted, so what was typed is not lost when switching */}
            <div class="panel" hidden={format !== 'jws'}>
                <JwsPanel mode={mode} initial={sharedJws ?? undefined} autoVerify={!!sharedJws?.token && !!sharedJws?.publicKey} />
            </div>
            <div class="panel" hidden={format !== 'sshsig'}>
                <SshsigPanel
                    mode={mode}
                    initialFile={initialFile}
                    initial={sharedSshsig ?? undefined}
                    autoVerify={!!sharedSshsig?.signature}
                />
            </div>
            <div class="panel" hidden={format !== 'minisign'}>
                <MinisignPanel
                    mode={mode}
                    initialFile={initialFile}
                    initial={sharedMinisign ?? undefined}
                    autoVerify={!!sharedMinisign?.signature}
                />
            </div>
            <div class="panel" hidden={format !== 'signify'}>
                <SignifyPanel
                    mode={mode}
                    initialFile={initialFile}
                    initial={sharedSignify ?? undefined}
                    autoVerify={!!sharedSignify?.signature}
                />
            </div>
            <div class="panel" hidden={format !== 'cose'}>
                <CosePanel mode={mode} initialFile={initialFile} initial={sharedCose ?? undefined} autoVerify={!!sharedCose?.message} />
            </div>
            <div class="panel" hidden={format !== 'pgp'}>
                <PgpPanel mode={mode} initialFile={initialFile} initial={sharedPgp ?? undefined} autoVerify={!!sharedPgp?.signature} />
            </div>
        </section>
    );
}
