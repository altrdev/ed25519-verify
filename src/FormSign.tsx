import { useEffect, useRef, useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import Field from './Field';
import { Icon } from './icons';
import MessageFormatSelector from './MessageFormatSelector';
import SelectorEncoding from './SelectorEncoding';
import VerifyEd25519, { generateKeyPair, InputError, type FieldErrors } from './signature';
import { encodingDefault } from './store';
import { MessageFormat, type SignEncoding } from './enum';

interface Props {
    message?: string;
    privateKey?: string;
    signature?: string;
}

export default function FormSign(props: Props) {
    const [message, setMessage] = useState(props.message ?? '');
    const [privateKey, setPrivateKey] = useState(props.privateKey ?? '');
    const [signature, setSignature] = useState(props.signature ?? '');
    const [publicKey, setPublicKey] = useState('');
    const [messageFormat, setMessageFormat] = useState(MessageFormat.Text);
    const [revealed, setRevealed] = useState(false);
    const [errors, setErrors] = useState<FieldErrors>({});
    const encoding = encodingDefault.value;

    // keystrokes can outpace the async derivation: only the latest one may update the field
    const derivation = useRef(0);
    const derive = async (key: string, enc: SignEncoding) => {
        const current = ++derivation.current;
        let derived = '';
        if (key.trim()) {
            try {
                derived = await new VerifyEd25519('', null, null, key).getPublicKey(enc);
            } catch {
                // incomplete or malformed key: nothing to show (the error appears on blur / on Sign)
            }
        }
        if (current === derivation.current) setPublicKey(derived);
    };

    // also covers the first render (initial key) and an encoding switch
    useEffect(() => {
        derive(privateKey, encoding);
    }, [encoding]);

    const reset = () => {
        setSignature('');
        setErrors({});
    };

    const onPrivateKeyInput = (value: string) => {
        setPrivateKey(value);
        setSignature('');
        setErrors((current) => ({ ...current, privateKey: undefined }));
        derive(value, encodingDefault.value);
    };

    const onPrivateKeyBlur = (value: string) => {
        if (!value.trim()) return;
        const found = new VerifyEd25519(message, null, null, value).validate(encodingDefault.value, ['privateKey']);
        setErrors((current) => ({ ...current, ...found }));
    };

    const onMessageInput = (value: string) => {
        setMessage(value);
        setSignature('');
        setErrors((current) => ({ ...current, message: undefined }));
    };

    const changeMessageFormat = (format: MessageFormat) => {
        setMessageFormat(format);
        setSignature('');
        setErrors((current) => ({ ...current, message: undefined }));
    };

    const generate = async () => {
        const pair = await generateKeyPair(encodingDefault.value);
        derivation.current++;
        setPrivateKey(pair.privateKey);
        setPublicKey(pair.publicKey);
        setRevealed(true);
        reset();
    };

    const performSign = async () => {
        const ed25519 = new VerifyEd25519(message, null, null, privateKey, messageFormat);
        const found = ed25519.validate(encodingDefault.value, ['privateKey', 'message']);
        setErrors(found);
        if (Object.keys(found).length > 0) {
            setSignature('');
            return;
        }
        try {
            setSignature(await ed25519.sign(encodingDefault.value));
        } catch (error) {
            setSignature('');
            setErrors(
                error instanceof InputError ? { [error.field]: error.message } : { privateKey: 'Signing failed.' }
            );
        }
    };

    return (
        <section class="card">
            <SelectorEncoding reset={reset} />
            <Field
                label="Private key"
                rows={2}
                value={privateKey}
                error={errors.privateKey}
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
                <button type="button" class="primary" onClick={performSign}>Sign</button>
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
