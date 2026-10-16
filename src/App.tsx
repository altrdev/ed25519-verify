import { useState } from 'preact/hooks';
import FormSigned from './FormSigned';
import FormSign from './FormSign';
import FormVerify from './FormVerify';
import { Icon } from './icons';
import { parseJwsShare, parseMinisignShare, parseShareFragment, parseSshsigShare } from './share';
import { theme } from './store';

const TABS = ['Verify signature', 'Sign message', 'Signed formats'];
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
    const [tab, setTab] = useState(sharedToken || sharedSshsig || sharedMinisign ? 2 : 0);
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
                    <FormVerify {...shared} autoVerify={shared?.publicKey !== undefined && shared?.signature !== undefined} />
                </div>
                <div role="tabpanel" hidden={tab !== 1}>
                    <FormSign />
                </div>
                <div role="tabpanel" hidden={tab !== 2}>
                    <FormSigned sharedJws={sharedToken} sharedSshsig={sharedSshsig} sharedMinisign={sharedMinisign} />
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
