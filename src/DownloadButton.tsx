import { downloadText } from './files';
import { Icon } from './icons';

interface Props {
    filename: string;
    text: string;
    /** accessible name, e.g. "Download private key" */
    label: string;
    onSaved?: () => void;
}

/** Saves a text as a file. Only by this click: nothing, a private key least of all, is ever saved unasked. */
export default function DownloadButton({ filename, text, label, onSaved }: Props) {
    return (
        <button
            type="button"
            class="chip"
            disabled={!text}
            aria-label={label}
            title={`Save as ${filename}`}
            onClick={() => {
                downloadText(filename, text);
                onSaved?.();
            }}
        >
            <Icon name="download" size={16} />
            Download
        </button>
    );
}
