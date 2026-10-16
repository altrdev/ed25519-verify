import { useEffect, useState } from 'preact/hooks';
import CopyButton from './CopyButton';
import Banner from './Banner';
import Field from './Field';
import FormatMenu, { readingFormat, readingHint, readingLabel } from './FormatMenu';
import { encodePublicKey, isKeyFile } from './keyfiles';
import MessageFormatSelector from './MessageFormatSelector';
import { MessageFormat, type FieldFormat, type RawFormat } from './enum';
import { shareFragment } from './share';
import VerifyEd25519, {
    encodeBytes,
    inspectField,
    type Field as FieldName,
    type FieldErrors,
    type FieldReading,
    type FormatOverrides,
    type Verdict,
} from './signature';

interface Props {
    message?: string;
    signature?: string;
    publicKey?: string;
    messageFormat?: MessageFormat;
    /** open with everything filled in (a share link): verify at once */
    autoVerify?: boolean;
}

export default function FormVerify(props: Props) {
    const [message, setMessage] = useState(props.message ?? '');
    const [signature, setSignature] = useState(props.signature ?? '');
    const [publicKey, setPublicKey] = useState(props.publicKey ?? '');
    const [verify, setVerify] = useState<Verdict | undefined>(undefined);
    const [messageFormat, setMessageFormat] = useState(props.messageFormat ?? MessageFormat.Text);
    const [errors, setErrors] = useState<FieldErrors>({});
    // when a text can be read in several formats the user picks one; the pick is dropped as soon as the text changes
    const [choices, setChoices] = useState<Partial<Record<FieldName, RawFormat[]>>>({});
    const [formats, setFormats] = useState<FormatOverrides>({});

    // what each text turned out to be, for the format menus and the "Detected" lines
    const publicKeyReading = inspectField('publicKey', publicKey, formats.publicKey);
    const signatureReading = inspectField('signature', signature, formats.signature);

    /** Picking a format rewrites the text in that format: the same bytes, written another way. */
    const convert = (field: 'publicKey' | 'signature', reading: FieldReading | null, format: FieldFormat) => {
        if (!reading) return;
        if (field === 'publicKey') setPublicKey(encodePublicKey(reading.bytes.slice(0, 32), format));
        else if (!isKeyFile(format)) setSignature(encodeBytes(reading.bytes, format));
        else return;
        setVerify(undefined);
        setErrors((current) => ({ ...current, [field]: undefined }));
        setChoices((current) => ({ ...current, [field]: undefined }));
        // the new text is read as picked, never asked about (key files are recognised by themselves)
        setFormats((current) => ({ ...current, [field]: isKeyFile(format) ? undefined : format }));
    };

    const formatMenu = (field: 'publicKey' | 'signature', reading: FieldReading | null, name: string) => (
        <FormatMenu
            name={name}
            kind={field === 'publicKey' ? 'public' : 'signature'}
            label={reading ? readingLabel(reading, field === 'publicKey' ? 'public' : 'signature') : 'Auto'}
            current={reading ? readingFormat(reading) : null}
            disabled={!reading}
            onSelect={(format) => convert(field, reading, format)}
        />
    );

    const edit = (set: (v: string) => void, field?: FieldName) => (value: string) => {
        set(value);
        setVerify(undefined);
        if (field) {
            setErrors((current) => ({ ...current, [field]: undefined }));
            setChoices((current) => ({ ...current, [field]: undefined }));
            setFormats((current) => ({ ...current, [field]: undefined }));
        }
    };

    const changeMessageFormat = (format: MessageFormat) => {
        setMessageFormat(format);
        setVerify(undefined);
        setErrors((current) => ({ ...current, message: undefined }));
    };

    const performVerify = async (picked: FormatOverrides = formats) => {
        const ed25519 = new VerifyEd25519(message, signature, publicKey, null, messageFormat, picked);
        const fields: FieldName[] = ['publicKey', 'message', 'signature'];
        const found = ed25519.validate(fields);
        setErrors(found);
        setChoices(ed25519.choices(fields));
        if (Object.keys(found).length > 0) {
            setVerify(undefined);
            return;
        }
        setVerify(await ed25519.verdict());
    };

    // a share link: the result is the first thing the reader sees
    useEffect(() => {
        if (props.autoVerify && publicKey && signature) performVerify();
    }, []);

    const link = () =>
        `${location.origin}${location.pathname}${location.search}${shareFragment({ publicKey, message, messageFormat, signature })}`;
    const shareable = shareFragment({ publicKey, message, messageFormat, signature }) !== '';

    const choose = (field: 'publicKey' | 'signature') => (format: RawFormat) => {
        const picked = { ...formats, [field]: format };
        setFormats(picked);
        performVerify(picked);
    };

    return (
        <section class="card">
            <Field
                label="Public key"
                rows={2}
                growWithContent
                value={publicKey}
                error={errors.publicKey}
                choices={choices.publicKey}
                onChoose={choose('publicKey')}
                hint={readingHint(publicKeyReading)}
                copyable
                formatControl={formatMenu('publicKey', publicKeyReading, 'Public key format')}
                placeholder="Hex, base64, PEM, OpenSSH or JWK"
                onInput={edit(setPublicKey, 'publicKey')}
            />
            <Field
                label="Message"
                rows={2}
                value={message}
                error={errors.message}
                actions={<MessageFormatSelector value={messageFormat} onChange={changeMessageFormat} />}
                onInput={edit(setMessage, 'message')}
            />
            <Field
                label="Signature"
                value={signature}
                error={errors.signature}
                choices={choices.signature}
                onChoose={choose('signature')}
                hint={readingHint(signatureReading)}
                copyable
                formatControl={formatMenu('signature', signatureReading, 'Signature format')}
                onInput={edit(setSignature, 'signature')}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={() => performVerify()}>
                    Verify
                </button>
                <CopyButton text={shareable ? link() : ''} label="Copy link to this verification" caption="Copy link" />
            </div>

            {verify === 'valid' && <Banner kind="success">Signature is valid</Banner>}
            {verify === 'invalid' && <Banner kind="error">Signature is wrong</Banner>}
            {verify === 'permissive-only' && (
                <Banner kind="warning">
                    Signature is not valid under the strict RFC 8032 rules, but it would be accepted under ZIP215, the more permissive rules
                    used by some systems (e.g. Zcash).
                </Banner>
            )}
        </section>
    );
}
