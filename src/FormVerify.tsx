import { useState } from 'preact/hooks';
import Banner from './Banner';
import Field from './Field';
import SelectorEncoding from './SelectorEncoding';
import VerifyEd25519, { type Field as FieldName, type FieldErrors } from './signature';
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
    const [verify, setVerify] = useState<boolean | undefined>(undefined);
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

    const performVerify = async () => {
        const encoding = encodingDefault.value;
        const ed25519 = new VerifyEd25519(message, signature, publicKey, null);
        const found = ed25519.validate(encoding, ['publicKey', 'signature']);
        setErrors(found);
        if (Object.keys(found).length > 0) {
            setVerify(undefined);
            return;
        }
        setVerify(await ed25519.check(encoding));
    };

    return (
        <section class="card">
            <SelectorEncoding reset={reset} />
            <Field label="Public key" rows={2} value={publicKey} error={errors.publicKey} onInput={edit(setPublicKey, 'publicKey')} />
            <Field label="Message" rows={2} value={message} onInput={edit(setMessage)} />
            <Field label="Signature" value={signature} error={errors.signature} onInput={edit(setSignature, 'signature')} />
            <div class="actions">
                <button type="button" class="primary" onClick={performVerify}>Verify</button>
            </div>

            {verify === true && <Banner kind="success">Signature is valid</Banner>}
            {verify === false && <Banner kind="error">Signature is wrong</Banner>}
        </section>
    );
}
