import { useState } from 'preact/hooks';
import Banner from './Banner';
import Field from './Field';
import SelectorEncoding from './SelectorEncoding';
import VerifyEd25519 from './signature';
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

    const resetVerify = () => setVerify(undefined);
    const edit = (set: (v: string) => void) => (value: string) => {
        set(value);
        resetVerify();
    };

    const performVerify = async () => {
        const ed25519 = new VerifyEd25519(message, signature, publicKey, null);
        setVerify(await ed25519.check(encodingDefault.value));
    };

    return (
        <div class="panel">
            <SelectorEncoding reset={resetVerify} />
            <Field label="Public key" rows={2} value={publicKey} onInput={edit(setPublicKey)} />
            <Field label="Message" rows={2} value={message} onInput={edit(setMessage)} />
            <Field label="Signature" value={signature} onInput={edit(setSignature)} />
            <button type="button" class="primary" onClick={performVerify}>Verify</button>

            {verify === true && <Banner kind="success">Signature is valid</Banner>}
            {verify === false && <Banner kind="error">Signature is wrong</Banner>}
        </div>
    );
}
