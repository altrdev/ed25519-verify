import { useEffect, useRef, useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import Field from './Field';
import FormatMenu, { readingFormat, readingHint, readingLabel } from './FormatMenu';
import { encodePrivateKey, encodePublicKey, isKeyFile, labelOf } from './keyfiles';
import { ExampleButton, ExampleNote, nextIndex } from './ExampleButton';
import { type Example, SIGNABLE_EXAMPLES } from './examples';
import { Icon } from './icons';
import MessageField from './MessageField';
import type { MessageFile } from './messagefile';
import VerifyEd25519, { encodeBytes, generateKeyPair, inspectField, InputError, type FieldErrors } from './signature';
import { formatPreference } from './store';
import { MessageFormat, type FieldFormat, type RawFormat } from './enum';
import { hexToBytes } from './bytes';
import { CODECS } from './codecs';

interface Props {
    message?: string;
    privateKey?: string;
}

export default function FormSign(props: Props) {
    const [message, setMessage] = useState(props.message ?? '');
    const [privateKey, setPrivateKey] = useState(props.privateKey ?? '');
    const [messageFormat, setMessageFormat] = useState(MessageFormat.Text);
    const [file, setFile] = useState<MessageFile | null>(null);
    const [revealed, setRevealed] = useState(false);
    const [errors, setErrors] = useState<FieldErrors>({});
    // a private key that can be read in several formats: the user picks one, until the text changes
    const [keyChoices, setKeyChoices] = useState<RawFormat[] | undefined>(undefined);
    const [keyFormat, setKeyFormat] = useState<RawFormat | undefined>(undefined);

    // results are kept as bytes and written in the chosen format when shown, so changing it does not lose anything
    const [signatureBytes, setSignatureBytes] = useState<Uint8Array | null>(null);
    const [publicKeyBytes, setPublicKeyBytes] = useState<Uint8Array | null>(null);
    const signature = signatureBytes ? encodeBytes(signatureBytes, formatPreference.signature.value) : '';
    const publicKey = publicKeyBytes ? encodePublicKey(publicKeyBytes, formatPreference.publicKey.value) : '';

    // an example loaded from the list: the signature it must give is the one published
    const [exampleIndex, setExampleIndex] = useState<number | null>(null);
    const [published, setPublished] = useState<Uint8Array | null>(null);
    const matchesPublished =
        !!signatureBytes &&
        !!published &&
        signatureBytes.length === published.length &&
        signatureBytes.every((byte, i) => byte === published[i]);

    const privateKeyReading = inspectField('privateKey', privateKey, keyFormat);

    /**
     * The private key is typed, so its menu converts the text; when there is nothing to convert (empty or not valid yet) it
     * only picks the format the key is written in when it is generated.
     */
    const pickPrivateKeyFormat = async (format: FieldFormat) => {
        formatPreference.privateKey.value = format;
        if (!privateKeyReading) return;
        const seed = privateKeyReading.bytes.slice(0, 32);
        let text: string;
        if (isKeyFile(format)) {
            const publicKey = await new VerifyEd25519('', null, null, privateKey, MessageFormat.Text, {
                privateKey: keyFormat,
            }).getPublicKeyBytes();
            text = encodePrivateKey(seed, publicKey, format);
        } else {
            text = encodeBytes(privateKeyReading.bytes, format);
        }
        setPrivateKey(text);
        setKeyFormat(isKeyFile(format) ? undefined : format); // the new text is read as picked, never asked about
        setKeyChoices(undefined);
        setSignatureBytes(null);
        setErrors((current) => ({ ...current, privateKey: undefined }));
    };

    // keystrokes can outpace the async derivation: only the latest one may update the field
    const derivation = useRef(0);
    const derive = async (key: string, format?: RawFormat) => {
        const current = ++derivation.current;
        let derived: Uint8Array | null = null;
        if (key.trim()) {
            try {
                derived = await new VerifyEd25519('', null, null, key, MessageFormat.Text, { privateKey: format }).getPublicKeyBytes();
            } catch {
                // incomplete or malformed key: nothing to show (the error appears on blur / on Sign)
            }
        }
        if (current === derivation.current) setPublicKeyBytes(derived);
    };

    // the key given as a property, if any
    useEffect(() => {
        derive(privateKey);
    }, []);

    const onPrivateKeyInput = (value: string) => {
        setPrivateKey(value);
        setSignatureBytes(null);
        setErrors((current) => ({ ...current, privateKey: undefined }));
        setKeyChoices(undefined);
        setKeyFormat(undefined);
        derive(value);
    };

    const onPrivateKeyBlur = (value: string) => {
        if (!value.trim()) return;
        const ed25519 = new VerifyEd25519(message, null, null, value, MessageFormat.Text, { privateKey: keyFormat });
        setErrors((current) => ({ ...current, ...ed25519.validate(['privateKey']) }));
        setKeyChoices(ed25519.choices(['privateKey']).privateKey);
    };

    const onMessageInput = (value: string) => {
        setMessage(value);
        setSignatureBytes(null);
        setErrors((current) => ({ ...current, message: undefined }));
    };

    const changeMessageFormat = (format: MessageFormat) => {
        setMessageFormat(format);
        setSignatureBytes(null);
        setErrors((current) => ({ ...current, message: undefined }));
    };

    const chooseFile = (chosen: MessageFile | null) => {
        setFile(chosen);
        setSignatureBytes(null);
        setErrors((current) => ({ ...current, message: undefined }));
    };

    const generate = async () => {
        const format = formatPreference.privateKey.value;
        const pair = await generateKeyPair(format);
        const override = isKeyFile(format) ? undefined : format;
        setPrivateKey(pair.privateKey);
        setKeyChoices(undefined);
        setKeyFormat(override); // written in this format, so read as such (a 43-character base58 key is also valid base64)
        derive(pair.privateKey, override);
        setRevealed(true);
        setSignatureBytes(null);
        setErrors({});
    };

    const loadExample = (example: Example) => {
        const key = example.privateKey ?? '';
        setPrivateKey(key);
        setMessage(example.message);
        setMessageFormat(example.messageFormat);
        setFile(null); // an example is typed text
        setKeyChoices(undefined);
        setKeyFormat(undefined);
        derive(key);
        setRevealed(true);
        setSignatureBytes(null);
        setErrors({});
        setPublished(hexToBytes(example.signature));
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, SIGNABLE_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(SIGNABLE_EXAMPLES[index]);
    };

    const performSign = async (format: RawFormat | undefined = keyFormat) => {
        const ed25519 = new VerifyEd25519(file?.bytes ?? message, null, null, privateKey, messageFormat, { privateKey: format });
        const found = ed25519.validate(['privateKey', 'message']);
        setErrors(found);
        setKeyChoices(ed25519.choices(['privateKey']).privateKey);
        if (Object.keys(found).length > 0) {
            setSignatureBytes(null);
            return;
        }
        try {
            setSignatureBytes(await ed25519.signBytes());
        } catch (error) {
            setSignatureBytes(null);
            setErrors(error instanceof InputError ? { [error.field]: error.message } : { privateKey: 'Signing failed.' });
        }
    };

    const chooseKeyFormat = (format: RawFormat) => {
        setKeyFormat(format);
        derive(privateKey, format);
        performSign(format);
    };

    return (
        <section class="card">
            <Field
                label="Private key"
                rows={2}
                growWithContent
                value={privateKey}
                error={errors.privateKey}
                choices={keyChoices}
                onChoose={chooseKeyFormat}
                hint={readingHint(privateKeyReading)}
                placeholder="Hex, base64, PEM, OpenSSH or JWK"
                secret
                revealed={revealed}
                onRevealedChange={setRevealed}
                copyable
                formatControl={
                    <FormatMenu
                        name="Private key format"
                        kind="private"
                        label={privateKeyReading ? readingLabel(privateKeyReading, 'private') : labelOf(formatPreference.privateKey.value)}
                        current={privateKeyReading ? readingFormat(privateKeyReading, 'private') : formatPreference.privateKey.value}
                        onSelect={pickPrivateKeyFormat}
                    />
                }
                actions={
                    <button type="button" class="chip" onClick={generate}>
                        <Icon name="plus" size={16} />
                        Generate
                    </button>
                }
                onInput={onPrivateKeyInput}
                onChange={onPrivateKeyBlur}
            />
            <Field
                label="Deduced Public key"
                rows={2}
                value={publicKey}
                copyable
                formatControl={
                    <FormatMenu
                        name="Public key format"
                        kind="public"
                        label={labelOf(formatPreference.publicKey.value)}
                        current={formatPreference.publicKey.value}
                        onSelect={(format) => (formatPreference.publicKey.value = format)}
                    />
                }
                disabled
                placeholder="Insert a private key (or generate one) to deduce it ..."
            />
            <MessageField
                value={message}
                onInput={onMessageInput}
                format={messageFormat}
                onFormatChange={changeMessageFormat}
                error={errors.message}
                file={file}
                onFile={chooseFile}
                onFileError={(error) => setErrors((current) => ({ ...current, message: error }))}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={() => performSign()}>
                    Sign
                </button>
                <ExampleButton onClick={loadNextExample} />
            </div>
            <ExampleNote example={exampleIndex === null ? null : SIGNABLE_EXAMPLES[exampleIndex]} />

            {signature && (
                <Banner kind="success">
                    <div class="result-head">
                        <strong>Signature:</strong>
                        <div class="field-actions">
                            <FormatMenu
                                name="Signature format"
                                kind="signature"
                                label={CODECS[formatPreference.signature.value].label}
                                current={formatPreference.signature.value}
                                onSelect={(format) => {
                                    if (!isKeyFile(format)) formatPreference.signature.value = format;
                                }}
                            />
                            <CopyButton text={signature} label="Copy signature" />
                        </div>
                    </div>
                    <div class="result">{signature}</div>
                    {matchesPublished && <p>Identical to the signature published in RFC 8032.</p>}
                </Banner>
            )}
        </section>
    );
}
