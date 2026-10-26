import { useState } from 'preact/hooks';
import FormSigned from './FormSigned';
import FormRaw from './FormRaw';
import { CONTAINER_LABELS, type Container, type Handoff, handoffFor } from './detect';
import { Icon } from './icons';
import type { MessageFile } from './messagefile';
import {
    parseCoseShare,
    parseJwsShare,
    parseMinisignShare,
    parsePgpShare,
    parseShareFragment,
    parseSignifyShare,
    parseSshsigShare,
} from './share';
import { theme } from './store';

type View = 'raw' | Container;

const RAW_VIEW: { view: View; label: string; note: string; blurb: string } = {
    view: 'raw',
    label: 'Raw signature',
    note: '64 bytes',
    blurb: 'Verify or create a signature from a public key, a message and the 64 bytes.',
};
const CONTAINER_VIEWS: { view: View; label: string; note: string; blurb: string }[] = [
    {
        view: 'jws',
        label: CONTAINER_LABELS.jws,
        note: 'RFC 7515',
        blurb: 'A token and its key: header, claims and times are shown apart from the verdict.',
    },
    {
        view: 'sshsig',
        label: CONTAINER_LABELS.sshsig,
        note: 'sshsig',
        blurb: 'What ssh-keygen -Y sign or git made, checked against a key or an allowed_signers file.',
    },
    {
        view: 'minisign',
        label: CONTAINER_LABELS.minisign,
        note: '.minisig',
        blurb: 'A .minisig, with the trusted comment kept apart from the one anyone can edit.',
    },
    {
        view: 'signify',
        label: CONTAINER_LABELS.signify,
        note: '.sig',
        blurb: 'The two line OpenBSD format: it signs the message itself, with no hash.',
    },
    {
        view: 'cose',
        label: CONTAINER_LABELS.cose,
        note: 'RFC 9052',
        blurb: 'COSE_Sign1 and COSE_Sign, one signature at a time, with the claims of a CWT by name.',
    },
    {
        view: 'pgp',
        label: CONTAINER_LABELS.pgp,
        note: 'verify only',
        blurb: 'A detached or cleartext signature against a key block. The mathematics only, never trust.',
    },
];
const VIEWS = [RAW_VIEW, ...CONTAINER_VIEWS];
const REPO_URL = 'https://github.com/altrdev/ed25519-verify';

/** `v2.6.0` linked to its release notes; a build that is not a release ("dev", "main-1a2b3c4") is shown as it is. */
export function VersionLabel({ version }: { version: string }) {
    if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) return <span title="Not a release">{version}</span>;
    return (
        <a href={`${REPO_URL}/releases/tag/v${version}`} target="_blank" rel="noopener noreferrer" title="Release notes">
            v{version}
        </a>
    );
}

export default function App() {
    // a link made by the Verify tab: its fields are filled in and checked at once
    const [shared] = useState(() => parseShareFragment(location.hash));
    // a link to a container opens the view that reads it
    const [sharedToken] = useState(() => parseJwsShare(location.hash));
    const [sharedSshsig] = useState(() => parseSshsigShare(location.hash));
    const [sharedMinisign] = useState(() => parseMinisignShare(location.hash));
    const [sharedSignify] = useState(() => parseSignifyShare(location.hash));
    const [sharedCose] = useState(() => parseCoseShare(location.hash));
    const [sharedPgp] = useState(() => parsePgpShare(location.hash));
    const [view, setView] = useState<View>(
        sharedPgp
            ? 'pgp'
            : sharedCose
              ? 'cose'
              : sharedSignify
                ? 'signify'
                : sharedMinisign
                  ? 'minisign'
                  : sharedSshsig
                    ? 'sshsig'
                    : sharedToken
                      ? 'jws'
                      : 'raw',
    );
    // a signature pasted in the Raw view that is a container (a JWT, an SSH signature...) opens in the view that reads it, with the rest
    const [handoff, setHandoff] = useState<{ id: number; data: Handoff; file: MessageFile | null } | null>(null);
    const openContainer = (format: Container, fields: Parameters<typeof handoffFor>[1], file: MessageFile | null) => {
        setHandoff((current) => ({ id: (current?.id ?? 0) + 1, data: handoffFor(format, fields), file }));
        setView(format);
    };
    const handed = <F extends Handoff['format']>(format: F, own: unknown) =>
        handoff?.data.format === format ? (handoff.data.shared as never) : (own as never);
    const dark = theme.value === 'dark';
    const current = VIEWS.find((v) => v.view === view) ?? RAW_VIEW;

    const tab = ({ view: id, label, note }: (typeof VIEWS)[number]) => (
        <button
            type="button"
            role="tab"
            key={id}
            aria-selected={view === id}
            aria-controls={id === 'raw' ? 'view-raw' : 'view-containers'}
            class={view === id ? 'active' : ''}
            onClick={() => setView(id)}
        >
            {label}
            <small aria-hidden="true">{note}</small>
        </button>
    );

    return (
        <>
            <header class="topbar">
                <div class="topbar-inner">
                    <div class="brand">
                        <span class="logo">
                            <Icon name="key" size={20} />
                        </span>
                        <h1>
                            Ed25519 <span>signature tools</span>
                        </h1>
                    </div>
                    <div class="topbar-actions">
                        <a
                            class="icon"
                            href={REPO_URL}
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label="View source on GitHub"
                            title="View source on GitHub"
                        >
                            <Icon name="github" size={22} />
                        </a>
                        <button
                            type="button"
                            class="icon"
                            aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
                            onClick={() => (theme.value = dark ? 'light' : 'dark')}
                        >
                            <Icon name={dark ? 'sun' : 'moon'} size={22} />
                        </button>
                    </div>
                </div>
            </header>
            <div class="app">
                <nav class="rail" aria-label="Signature formats">
                    <div class="rail-group">
                        <h2>Raw</h2>
                        <div role="tablist" aria-orientation="vertical" aria-label="Raw">
                            {tab(RAW_VIEW)}
                        </div>
                    </div>
                    <div class="rail-group">
                        <h2>Containers</h2>
                        <div role="tablist" aria-orientation="vertical" aria-label="Containers">
                            {CONTAINER_VIEWS.map(tab)}
                        </div>
                    </div>
                </nav>
                <main class="bench">
                    <div class="bench-head">
                        <h2>{current.label}</h2>
                        <p class="lead">{current.blurb} Everything runs in your browser, nothing is uploaded.</p>
                    </div>
                    {/* both views stay mounted so switching does not lose what was typed */}
                    <div id="view-raw" role="tabpanel" hidden={view !== 'raw'}>
                        <FormRaw
                            {...shared}
                            autoVerify={shared?.publicKey !== undefined && shared?.signature !== undefined}
                            onOpenContainer={openContainer}
                        />
                    </div>
                    <div id="view-containers" role="tabpanel" hidden={view === 'raw'}>
                        <FormSigned
                            key={handoff?.id ?? 0}
                            format={view === 'raw' ? 'jws' : view}
                            sharedJws={handed('jws', sharedToken)}
                            sharedSshsig={handed('sshsig', sharedSshsig)}
                            sharedMinisign={handed('minisign', sharedMinisign)}
                            sharedSignify={handed('signify', sharedSignify)}
                            sharedCose={handed('cose', sharedCose)}
                            sharedPgp={handed('pgp', sharedPgp)}
                            initialFile={handoff?.file ?? null}
                        />
                    </div>
                </main>
            </div>
            <footer class="footer">
                <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
                    Open source on GitHub
                </a>
                <span aria-hidden="true">·</span>
                <span>MIT License</span>
                <span aria-hidden="true">·</span>
                <VersionLabel version={__APP_VERSION__} />
            </footer>
        </>
    );
}
