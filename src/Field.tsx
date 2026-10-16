import type { ComponentChildren } from 'preact';
import { useId, useRef, useState } from 'preact/hooks';
import { CODECS } from './codecs';
import CopyButton from './CopyButton';
import type { RawFormat } from './enum';
import DownloadButton from './DownloadButton';
import { type FileKind, FileError, readFileForField } from './files';
import { Icon } from './icons';

interface FieldProps {
    label: string;
    value: string;
    rows?: number;
    /** grow with the number of lines (up to 8), so a pasted multi-line value such as a PEM is visible */
    growWithContent?: boolean;
    disabled?: boolean;
    placeholder?: string;
    /** validation message, shown under the field */
    error?: string;
    /** neutral note under the field (hidden while there is an error) */
    hint?: string;
    /** formats the pasted text can be read in, when it is ambiguous: shown as buttons under the error */
    choices?: RawFormat[];
    onChoose?: (format: RawFormat) => void;
    /** other buttons under the error: each one settles the question it asks (which key of a set to use) */
    picks?: { label: string; onPick: () => void }[];
    /** extra buttons on the label row */
    actions?: ComponentChildren;
    /** the format menu, placed before the copy button */
    formatControl?: ComponentChildren;
    /** copy button on the label row */
    copyable?: boolean;
    /** hide the content (like a password) with a show/hide toggle */
    secret?: boolean;
    /** controlled visibility of a secret field; uncontrolled when omitted */
    revealed?: boolean;
    onRevealedChange?: (revealed: boolean) => void;
    /** lets a file be opened or dropped into the field: what the file may be (a key, a signature) */
    fileKind?: FileKind;
    /** a button that saves the content as a file */
    download?: { filename: string; secret?: boolean };
    /** shown instead of the text area (e.g. a file chosen as the value) */
    content?: ComponentChildren;
    /** something is being dragged over the field (when the caller handles the drop itself) */
    dragging?: boolean;
    onInput?: (value: string) => void;
    onChange?: (value: string) => void;
}

export default function Field({
    label,
    value,
    rows = 3,
    growWithContent,
    disabled,
    placeholder,
    error,
    hint,
    choices,
    onChoose,
    picks,
    actions,
    formatControl,
    copyable,
    secret,
    revealed: revealedProp,
    onRevealedChange,
    fileKind,
    download,
    content,
    dragging: draggingProp,
    onInput,
    onChange,
}: FieldProps) {
    const id = useId();
    const errorId = `${id}-error`;
    const [revealedState, setRevealedState] = useState(false);
    const revealed = revealedProp ?? revealedState;
    const masked = secret && !revealed;
    const lineCount = value.replace(/\n+$/, '').split('\n').length;
    const visibleRows = growWithContent ? Math.min(Math.max(rows, lineCount), 8) : rows;

    // a file opened or dropped here: read in the browser, its text goes in the field as if it had been pasted
    const fileInput = useRef<HTMLInputElement>(null);
    const [fileError, setFileError] = useState<string | undefined>(undefined);
    const [draggedOver, setDraggedOver] = useState(false);
    const dragging = draggingProp || draggedOver;
    // after saving a private key: the file is not encrypted
    const [savedAs, setSavedAs] = useState<string | undefined>(undefined);
    const openFile = async (file: File | undefined) => {
        if (!file || !fileKind) return;
        try {
            const text = await readFileForField(file, fileKind);
            setFileError(undefined);
            onInput?.(text);
            onChange?.(text);
        } catch (error) {
            if (!(error instanceof FileError)) throw error;
            setFileError(error.message);
        }
    };
    const hasFiles = (event: DragEvent) => !!event.dataTransfer && Array.from(event.dataTransfer.types).includes('Files');

    const toggleReveal = () => {
        setRevealedState(!revealed);
        onRevealedChange?.(!revealed);
    };

    return (
        <div class={`field${error ? ' invalid' : ''}${dragging ? ' dragging' : ''}`}>
            <div class="field-head">
                <label for={id}>{label}</label>
                <div class="field-actions">
                    {actions}
                    {secret && (
                        <button
                            type="button"
                            class="chip"
                            aria-label={`${revealed ? 'Hide' : 'Show'} ${label.toLowerCase()}`}
                            aria-pressed={revealed}
                            onClick={toggleReveal}
                        >
                            <Icon name={revealed ? 'eyeOff' : 'eye'} size={16} />
                            {revealed ? 'Hide' : 'Show'}
                        </button>
                    )}
                    {formatControl}
                    {copyable && <CopyButton text={value} label={`Copy ${label.toLowerCase()}`} />}
                    {download && (
                        <DownloadButton
                            filename={download.filename}
                            text={value}
                            label={`Download ${label.toLowerCase()}`}
                            onSaved={() => setSavedAs(download.secret ? download.filename : undefined)}
                        />
                    )}
                    {fileKind && (
                        <>
                            <input
                                ref={fileInput}
                                type="file"
                                hidden
                                aria-label={`File for ${label.toLowerCase()}`}
                                onChange={(e) => {
                                    openFile(e.currentTarget.files?.[0]);
                                    e.currentTarget.value = ''; // the same file can be opened again
                                }}
                            />
                            <button
                                type="button"
                                class="chip"
                                aria-label={`Choose file for ${label.toLowerCase()}`}
                                onClick={() => fileInput.current?.click()}
                            >
                                <Icon name="upload" size={16} />
                                Choose file
                            </button>
                        </>
                    )}
                </div>
            </div>
            {content ?? (
                <textarea
                    id={id}
                    class={masked ? 'masked' : ''}
                    rows={visibleRows}
                    value={value}
                    disabled={disabled}
                    placeholder={placeholder}
                    spellcheck={false}
                    autocomplete="off"
                    autocapitalize="off"
                    aria-invalid={error ? true : undefined}
                    aria-describedby={error ? errorId : undefined}
                    onDragOver={(e) => {
                        if (!fileKind || !hasFiles(e)) return;
                        e.preventDefault(); // allows the drop
                        setDraggedOver(true);
                    }}
                    onDragLeave={() => setDraggedOver(false)}
                    onDrop={(e) => {
                        if (!fileKind || !hasFiles(e)) return;
                        e.preventDefault();
                        setDraggedOver(false);
                        openFile(e.dataTransfer?.files[0]);
                    }}
                    onInput={(e) => {
                        setFileError(undefined);
                        setSavedAs(undefined);
                        onInput?.(e.currentTarget.value);
                    }}
                    onChange={(e) => onChange?.(e.currentTarget.value)}
                />
            )}
            {error && (
                <p class="field-error" id={errorId} role="alert">
                    {error}
                </p>
            )}
            {savedAs && (
                <p class="field-hint" role="status">
                    Saved as {savedAs}. This file is not encrypted: keep it somewhere safe.
                </p>
            )}
            {fileError && !error && (
                <p class="field-error" role="alert">
                    {fileError}
                </p>
            )}
            {error && choices && choices.length > 0 && (
                <div class="field-choices">
                    {choices.map((format) => (
                        <button type="button" class="chip" key={format} onClick={() => onChoose?.(format)}>
                            Read as {CODECS[format].label.toLowerCase()}
                        </button>
                    ))}
                </div>
            )}
            {error && picks && picks.length > 0 && (
                <div class="field-choices">
                    {picks.map((pick) => (
                        <button type="button" class="chip" key={pick.label} onClick={pick.onPick}>
                            {pick.label}
                        </button>
                    ))}
                </div>
            )}
            {hint && !error && !savedAs && <p class="field-hint">{hint}</p>}
        </div>
    );
}
