import { useState } from 'preact/hooks';
import Banner from './Banner';
import Field from './Field';
import MessageFormatSelector from './MessageFormatSelector';
import SelectorEncoding from './SelectorEncoding';
import { MessageFormat } from './enum';
import VerifyEd25519, { type Field as FieldName, type FieldErrors, type Verdict } from './signature';
import { keyFormatHint } from './keyformats';
import { encodingDefault } from './store';

interface Props {
    message?: string;
    signature?: string;
    publicKey?: string;
}

export default function FormVerify(props: Props) {
    const [message, setMessage] = useState(props.message ?? '');
    const [signature, setSignature] = useState(props.signature ?? '');
    const [publicKey, setPublicKey] = useState(props.publicKey ?? '');
    const [verify, setVerify] = useState<Verdict | undefined>(undefined);
    const [messageFormat, setMessageFormat] = useState(MessageFormat.Text);
    const [errors, setErrors] = useState<FieldErrors>({});

    const reset = () => {
        setVerify(undefined);
        setErrors({});
    };

    const edit = (set: (v: string) => void, field?: FieldName) => (value: string) => {
        set(value);
        setVerify(undefined);
        if (field) setErrors((current) => ({ ...current, [field]: undefined }));
    };

    const changeMessageFormat = (format: MessageFormat) => {
        setMessageFormat(format);
        setVerify(undefined);
        setErrors((current) => ({ ...current, message: undefined }));
    };

    const performVerify = async () => {
        const encoding = encodingDefault.value;
        const ed25519 = new VerifyEd25519(message, signature, publicKey, null, messageFormat);
        const found = ed25519.validate(encoding, ['publicKey', 'message', 'signature']);
        setErrors(found);
        if (Object.keys(found).length > 0) {
            setVerify(undefined);
            return;
        }
        setVerify(await ed25519.verdict(encoding));
    };

    return (
        <section class="card">
            <SelectorEncoding reset={reset} />
            <Field
                label="Public key"
                rows={2}
                growWithContent
                value={publicKey}
                error={errors.publicKey}
                hint={keyFormatHint(publicKey)}
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
            <Field label="Signature" value={signature} error={errors.signature} onInput={edit(setSignature, 'signature')} />
            <div class="actions">
                <button type="button" class="primary" onClick={performVerify}>Verify</button>
            </div>

            {verify === 'valid' && <Banner kind="success">Signature is valid</Banner>}
            {verify === 'invalid' && <Banner kind="error">Signature is wrong</Banner>}
            {verify === 'permissive-only' && (
                <Banner kind="warning">
                    Signature is not valid under the strict RFC 8032 rules, but it would be accepted under ZIP215,
                    the more permissive rules used by some systems (e.g. Zcash).
                </Banner>
            )}
        </section>
    );
}
