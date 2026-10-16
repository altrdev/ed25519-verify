import { useState } from 'preact/hooks';
import FormSign from './FormSign';
import FormVerify from './FormVerify';
import { Icon } from './icons';
import { theme } from './store';

const TABS = ['Verify signature', 'Sign message'];

export default function App() {
    const [tab, setTab] = useState(0);
    const dark = theme.value === 'dark';

    return (
        <>
            <header class="topbar">
                <div class="topbar-inner">
                    <div class="brand">
                        <span class="logo"><Icon name="key" size={20} /></span>
                        <h1>Ed25519 <span>signature tools</span></h1>
                    </div>
                    <button
                        type="button"
                        class="icon"
                        aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
                        onClick={() => (theme.value = dark ? 'light' : 'dark')}
                    >
                        <Icon name={dark ? 'sun' : 'moon'} size={22} />
                    </button>
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
                <div role="tabpanel" hidden={tab !== 0}><FormVerify /></div>
                <div role="tabpanel" hidden={tab !== 1}><FormSign /></div>
            </main>
        </>
    );
}
