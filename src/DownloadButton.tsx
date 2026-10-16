import { downloadBytes, downloadText } from './files';
import { Icon } from './icons';

interface Props {
    filename: string;
    text: string;
    /** save these bytes instead of the text (a binary file) */
    bytes?: Uint8Array;
    /** accessible name, e.g. "Download private key" */
    label: string;
    onSaved?: () => void;
}

/** Saves a text as a file. Only by this click: nothing, a private key least of all, is ever saved unasked. */
export default function DownloadButton({ filename, text, bytes, label, onSaved }: Props) {
    return (
        <button
            type="button"
            class="chip"
            disabled={!text && !bytes}
            aria-label={label}
            title={`Save as ${filename}`}
            onClick={() => {
                if (bytes) downloadBytes(filename, bytes);
                else downloadText(filename, text);
                onSaved?.();
            }}
        >
            <Icon name="download" size={16} />
            Download
        </button>
    );
}
