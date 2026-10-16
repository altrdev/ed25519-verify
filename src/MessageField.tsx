import { useRef, useState } from 'preact/hooks';
import Field from './Field';
import MessageFormatSelector from './MessageFormatSelector';
import type { MessageFormat } from './enum';
import { describeFile, type MessageFile, readMessageFile } from './messagefile';

interface Props {
    /** the label of the field ("Message") */
    label?: string;
    hint?: string;
    value: string;
    onInput: (value: string) => void;
    format: MessageFormat;
    onFormatChange: (format: MessageFormat) => void;
    error?: string;
    file: MessageFile | null;
    /** a file was chosen, or null to go back to typing */
    onFile: (file: MessageFile | null) => void;
    /** the file chosen could not be used (too large, unreadable) */
    onFileError: (message: string) => void;
}

/** The message: typed (with its format) or read from a file chosen or dropped here. */
export default function MessageField({
    label = 'Message',
    hint,
    value,
    onInput,
    format,
    onFormatChange,
    error,
    file,
    onFile,
    onFileError,
}: Props) {
    const picker = useRef<HTMLInputElement>(null);
    const [dragging, setDragging] = useState(false);

    const take = async (chosen: File | undefined) => {
        if (!chosen) return;
        const read = await readMessageFile(chosen);
        if (typeof read === 'string') onFileError(read);
        else onFile(read);
    };

    const actions = file ? (
        <button type="button" class="chip" onClick={() => onFile(null)}>
            Type a message
        </button>
    ) : (
        <>
            <button type="button" class="chip" onClick={() => picker.current?.click()}>
                Choose file
            </button>
            <MessageFormatSelector value={format} onChange={onFormatChange} />
        </>
    );

    return (
        // biome-ignore lint/a11y/noStaticElementInteractions: drag and drop is an extra way to choose a file, the button does the same
        <div
            onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                take(e.dataTransfer?.files?.[0]);
            }}
        >
            <input
                ref={picker}
                type="file"
                hidden
                aria-label="Message file"
                onChange={(e) => {
                    take(e.currentTarget.files?.[0]);
                    e.currentTarget.value = ''; // the same file can be chosen again
                }}
            />
            <Field
                label={label}
                hint={hint}
                rows={2}
                value={value}
                error={error}
                dragging={dragging}
                actions={actions}
                content={file ? <div class="file-message">{describeFile(file)}</div> : undefined}
                onInput={onInput}
            />
        </div>
    );
}
