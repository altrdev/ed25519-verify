import { useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
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
        <section class="card">
            <SelectorEncoding reset={() => setSignature('')} />
            <Field label="Private key" rows={2} secret value={privateKey} onInput={setPrivateKey} onChange={deductPublicKey} />
            <Field
                label="Deduced Public key"
                rows={2}
                value={publicKey}
                copyable
                disabled
                placeholder="Insert private key for deducing ..."
            />
            <Field label="Message (Plain text)" rows={2} value={message} onInput={setMessage} />
            <div class="actions">
                <button type="button" class="primary" onClick={performSign}>Sign</button>
            </div>

            {signature === null && (
                <Banner kind="error">Signature can't be performed. Private key is mandatory</Banner>
            )}
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
