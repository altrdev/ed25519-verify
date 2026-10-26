import { useEffect, useRef } from 'preact/hooks';
import { Icon } from './icons';

const FORMATS: { name: string; made: string }[] = [
    { name: 'JWS / JWT', made: 'a token that starts with eyJ, from an auth library or server' },
    { name: 'SSH signature', made: 'ssh-keygen -Y sign, also what git makes with gpg.format=ssh' },
    { name: 'minisign', made: 'minisign -S, a .minisig file' },
    { name: 'signify', made: 'signify -S, a .sig file' },
    { name: 'COSE', made: 'a CBOR message (COSE_Sign1, COSE_Sign, a CWT) as hex, base64 or a .cose file' },
    { name: 'OpenPGP', made: 'gpg --detach-sign or a cleartext signed message (verify only)' },
];

const FOCUSABLE = 'a[href], button:not(:disabled), [tabindex]:not([tabindex="-1"])';

/** What the page is, how to read its answer, and which view reads which file. A dialog: Escape, the close button and a click outside close it. */
export default function Help({ onClose }: { onClose: () => void }) {
    const panel = useRef<HTMLDivElement>(null);

    useEffect(() => {
        panel.current?.querySelector<HTMLElement>('button')?.focus();
        document.body.style.overflow = 'hidden';
        return () => {
            document.body.style.overflow = '';
        };
    }, []);

    const keep = (event: KeyboardEvent) => {
        if (event.key === 'Escape') {
            event.stopPropagation();
            onClose();
        } else if (event.key === 'Tab' && panel.current) {
            // the focus stays inside the dialog
            const items = Array.from(panel.current.querySelectorAll<HTMLElement>(FOCUSABLE));
            const first = items[0];
            const last = items[items.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        }
    };

    return (
        // biome-ignore lint/a11y/noStaticElementInteractions: the overlay only catches a click outside the dialog; the keyboard closes it with Escape
        <div class="overlay" onClick={(e) => e.target === e.currentTarget && onClose()} onKeyDown={keep}>
            <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="help-title" ref={panel}>
                <div class="dialog-head">
                    <h2 id="help-title">What is this?</h2>
                    <button type="button" class="icon" aria-label="Close" onClick={onClose}>
                        <Icon name="close" size={20} />
                    </button>
                </div>
                {/* biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be focusable, so that the keyboard can scroll it (axe) */}
                <div class="dialog-body" tabIndex={0}>
                    <section>
                        <h3>What it does</h3>
                        <p>
                            Verifies and creates Ed25519 signatures (RFC 8032): raw ones, and those inside a JWT, an SSH signature,
                            minisign, signify, COSE or OpenPGP. Everything runs in your browser, nothing is uploaded, and after the first
                            visit it works offline. A private key is never put in a link.
                        </p>
                    </section>
                    <section>
                        <h3>How to read the result</h3>
                        <ul>
                            <li>
                                <strong>Signature is valid</strong> means this key signed exactly these bytes. It does not mean the key is
                                one to trust: SSH asks for the key you trust, and OpenPGP is never called trusted here.
                            </li>
                            <li>
                                <strong>Signature is wrong</strong> does not say which input is at fault, because Ed25519 cannot. The page
                                retries the usual mistakes (a newline, hex read as text, the two halves swapped) and tells you which one
                                works.
                            </li>
                            <li>A token can be correctly signed and expired: the two answers are kept apart.</li>
                        </ul>
                    </section>
                    <section>
                        <h3>Which view for which file</h3>
                        <dl class="formats">
                            {FORMATS.map((format) => (
                                <div key={format.name}>
                                    <dt>{format.name}</dt>
                                    <dd>{format.made}</dd>
                                </div>
                            ))}
                        </dl>
                        <p>
                            Paste one of these in the signature field of <em>Raw signature</em> and the page names it and offers to open it
                            in the right view.
                        </p>
                    </section>
                    <section>
                        <h3>To try it</h3>
                        <p>
                            <em>Load example</em> fills the form with the test vectors of RFC 8032. The yellow warning is for a signature
                            that only the permissive ZIP215 rules accept (used by some systems, such as Zcash) and the strict RFC rules
                            refuse.
                        </p>
                    </section>
                </div>
            </div>
        </div>
    );
}
