import { useEffect, useState } from 'preact/hooks';
import { Icon } from './icons';

export default function CopyButton({ text, label, caption = 'Copy' }: { text: string; label: string; caption?: string }) {
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        if (!copied) return;
        const timer = setTimeout(() => setCopied(false), 1500);
        return () => clearTimeout(timer);
    }, [copied]);

    const copy = async () => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
        } catch {
            // clipboard blocked (insecure context, permissions): nothing to do
        }
    };

    return (
        <button type="button" class="chip" disabled={!text} aria-label={label} onClick={copy}>
            <Icon name={copied ? 'check' : 'copy'} size={16} />
            {copied ? 'Copied' : caption}
        </button>
    );
}
