import { useEffect, useRef, useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import Field from './Field';
import { Icon } from './icons';
import { keyFormatHint } from './keyformats';
import MessageFormatSelector from './MessageFormatSelector';
import SelectorEncoding from './SelectorEncoding';
import VerifyEd25519, { encodeBytes, generateKeyPair, InputError, type FieldErrors } from './signature';
import { outputEncoding } from './store';
import { MessageFormat, type RawFormat } from './enum';

interface Props {
    message?: string;
    privateKey?: string;
}

export default function FormSign(props: Props) {
    const [message, setMessage] = useState(props.message ?? '');
    const [privateKey, setPrivateKey] = useState(props.privateKey ?? '');
    const [messageFormat, setMessageFormat] = useState(MessageFormat.Text);
    const [revealed, setRevealed] = useState(false);
    const [errors, setErrors] = useState<FieldErrors>({});
    // a private key that can be read in several formats: the user picks one, until the text changes
    const [keyChoices, setKeyChoices] = useState<RawFormat[] | undefined>(undefined);
    const [keyFormat, setKeyFormat] = useState<RawFormat | undefined>(undefined);

    // results are kept as bytes and written in the chosen encoding when shown, so changing it does not lose anything
    const [signatureBytes, setSignatureBytes] = useState<Uint8Array | null>(null);
    const [publicKeyBytes, setPublicKeyBytes] = useState<Uint8Array | null>(null);
    const encoding = outputEncoding.value;
    const signature = signatureBytes ? encodeBytes(signatureBytes, encoding) : '';
    const publicKey = publicKeyBytes ? encodeBytes(publicKeyBytes, encoding) : '';

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

    const generate = async () => {
        const pair = await generateKeyPair(outputEncoding.value);
        setPrivateKey(pair.privateKey);
        setKeyChoices(undefined);
        setKeyFormat(undefined);
        derive(pair.privateKey);
        setRevealed(true);
        setSignatureBytes(null);
        setErrors({});
    };

    const performSign = async (format: RawFormat | undefined = keyFormat) => {
        const ed25519 = new VerifyEd25519(message, null, null, privateKey, messageFormat, { privateKey: format });
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
            setErrors(
                error instanceof InputError ? { [error.field]: error.message } : { privateKey: 'Signing failed.' }
            );
        }
    };

    const chooseKeyFormat = (format: RawFormat) => {
        setKeyFormat(format);
        derive(privateKey, format);
        performSign(format);
    };

    return (
        <section class="card">
            <SelectorEncoding />
            <Field
                label="Private key"
                rows={2}
                growWithContent
                value={privateKey}
                error={errors.privateKey}
                choices={keyChoices}
                onChoose={chooseKeyFormat}
                hint={keyFormatHint(privateKey)}
                placeholder="Hex, base64, PEM, OpenSSH or JWK"
                secret
                revealed={revealed}
                onRevealedChange={setRevealed}
                copyable
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
                disabled
                placeholder="Insert a private key (or generate one) to deduce it ..."
            />
            <Field
                label="Message"
                rows={2}
                value={message}
                error={errors.message}
                actions={<MessageFormatSelector value={messageFormat} onChange={changeMessageFormat} />}
                onInput={onMessageInput}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={() => performSign()}>Sign</button>
            </div>

            {signature && (
                <Banner kind="success">
                    <div class="result-head">
                        <strong>Signature:</strong>
                        <CopyButton text={signature} label="Copy signature" />
                    </div>
                    <div class="result">{signature}</div>
                </Banner>
            )}
        </section>
    );
}
