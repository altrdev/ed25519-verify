import { useState } from 'preact/hooks';
import FormSigned from './FormSigned';
import FormSign from './FormSign';
import FormVerify from './FormVerify';
import { type Container, type Handoff, handoffFor } from './detect';
import { Icon } from './icons';
import type { MessageFile } from './messagefile';
import { parseCoseShare, parseJwsShare, parseMinisignShare, parsePgpShare, parseShareFragment, parseSshsigShare } from './share';
import { theme } from './store';

const TABS = ['Verify signature', 'Sign message', 'Tokens and files'];
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
    // a link to a token opens the tab of the signed formats
    const [sharedToken] = useState(() => parseJwsShare(location.hash));
    const [sharedSshsig] = useState(() => parseSshsigShare(location.hash));
    const [sharedMinisign] = useState(() => parseMinisignShare(location.hash));
    const [sharedCose] = useState(() => parseCoseShare(location.hash));
    const [sharedPgp] = useState(() => parsePgpShare(location.hash));
    const [tab, setTab] = useState(sharedToken || sharedSshsig || sharedMinisign || sharedCose || sharedPgp ? 2 : 0);
    // a signature pasted in the Verify tab that is a container (a JWT, an SSH signature...) opens in the tab that reads it, with the rest
    const [handoff, setHandoff] = useState<{ id: number; data: Handoff; file: MessageFile | null } | null>(null);
    const openContainer = (format: Container, fields: Parameters<typeof handoffFor>[1], file: MessageFile | null) => {
        setHandoff((current) => ({ id: (current?.id ?? 0) + 1, data: handoffFor(format, fields), file }));
        setTab(2);
    };
    const handed = <F extends Handoff['format']>(format: F, own: unknown) =>
        handoff?.data.format === format ? (handoff.data.shared as never) : (own as never);
    const dark = theme.value === 'dark';

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
            <main class="container">
                <p class="lead">Verify and create Ed25519 signatures. Everything runs in your browser, nothing is uploaded.</p>
                <div class="segmented" role="tablist">
                    {TABS.map((label, i) => (
                        <button
                            type="button"
                            role="tab"
                            key={label}
                            aria-selected={tab === i}
                            class={tab === i ? 'active' : ''}
                            onClick={() => setTab(i)}
                        >
                            {label}
                        </button>
                    ))}
                </div>
                {/* both forms stay mounted so switching tab does not lose what was typed */}
                <div role="tabpanel" hidden={tab !== 0}>
                    <FormVerify
                        {...shared}
                        autoVerify={shared?.publicKey !== undefined && shared?.signature !== undefined}
                        onOpenContainer={openContainer}
                    />
                </div>
                <div role="tabpanel" hidden={tab !== 1}>
                    <FormSign />
                </div>
                <div role="tabpanel" hidden={tab !== 2}>
                    <FormSigned
                        key={handoff?.id ?? 0}
                        sharedJws={handed('jws', sharedToken)}
                        sharedSshsig={handed('sshsig', sharedSshsig)}
                        sharedMinisign={handed('minisign', sharedMinisign)}
                        sharedCose={handed('cose', sharedCose)}
                        sharedPgp={handed('pgp', sharedPgp)}
                        initialFile={handoff?.file ?? null}
                    />
                </div>
            </main>
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
