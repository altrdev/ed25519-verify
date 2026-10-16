import { useState } from 'preact/hooks';
import Banner from './Banner';
import Field from './Field';
import SelectorEncoding from './SelectorEncoding';
import VerifyEd25519 from './signature';
import { encodingDefault } from './store';

interface Props {
    message?: string;
    privateKey?: string;
    signature?: string;
}

export default function FormSign(props: Props) {
    const [message, setMessage] = useState(props.message ?? '');
    const [privateKey, setPrivateKey] = useState(props.privateKey ?? '');
    // '' = nothing to show, null = signing failed, string = the signature
    const [signature, setSignature] = useState<string | null>(props.signature ?? '');
    const [publicKey, setPublicKey] = useState('');

    const performSign = async () => {
        const ed25519 = new VerifyEd25519(message, null, null, privateKey);
        setSignature(await ed25519.sign(encodingDefault.value));
    };

    const deductPublicKey = async (key: string) => {
        const ed25519 = new VerifyEd25519(message, null, null, key);
        setPublicKey((await ed25519.getPublicKey(encodingDefault.value)) ?? '');
    };

    return (
        <div class="panel">
            <SelectorEncoding reset={() => setSignature('')} />
            <Field label="Private key" rows={2} value={privateKey} onInput={setPrivateKey} onChange={deductPublicKey} />
            <Field
                label="Deduced Public key"
                rows={2}
                value={publicKey}
                disabled
                placeholder="Insert private key for deducing ..."
            />
            <Field label="Message (Plain text)" rows={2} value={message} onInput={setMessage} />
            <button type="button" class="primary" onClick={performSign}>Sign</button>

            {signature === null && (
                <Banner kind="error">Signature can't be performed. Private key is mandatory</Banner>
            )}
            {signature && (
                <Banner kind="success">
                    Signature:
                    <div class="result">{signature}</div>
                </Banner>
            )}
        </div>
    );
}
