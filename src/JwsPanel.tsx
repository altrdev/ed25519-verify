import { useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import DownloadButton from './DownloadButton';
import { fileNameFor } from './files';
import Field from './Field';
import {
    bytesOfInput,
    checkHeaderToSign,
    describePayload,
    JwsError,
    type ParsedJws,
    type PayloadInfo,
    parseJws,
    signingInputOf,
    timeNotes,
    tokenOf,
} from './jws';
import { encodeJwk } from './keyfiles';
import { readingHint } from './FormatMenu';
import type { RawFormat } from './enum';
import VerifyEd25519, { inspectField, type FormatOverrides, InputError, type Verdict, verdictOf } from './signature';

interface Shown {
    verdict: Verdict;
    parsed: ParsedJws;
    info: PayloadInfo;
    notes: string[];
}

/** The decoded token: what it says, which is not what the signature proves. */
function Decoded({ shown }: { shown: Shown }) {
    const { parsed, info, notes } = shown;
    return (
        <section class="decoded" aria-label="Token contents">
            <h2>Header</h2>
            <pre>{JSON.stringify(parsed.header, null, 2)}</pre>
            <h2>Payload</h2>
            {info.json && <pre>{info.json}</pre>}
            {!info.json && info.text !== null && <pre>{info.text}</pre>}
            {info.text === null && <p>The payload is not text ({parsed.payload.length} bytes).</p>}
            {notes.length > 0 && (
                <ul>
                    {notes.map((note) => (
                        <li key={note}>{note}</li>
                    ))}
                </ul>
            )}
        </section>
    );
}

function Verify() {
    const [token, setToken] = useState('');
    const [publicKey, setPublicKey] = useState('');
    const [errors, setErrors] = useState<{ token?: string; publicKey?: string }>({});
    const [choices, setChoices] = useState<RawFormat[] | undefined>(undefined);
    const [formats, setFormats] = useState<FormatOverrides>({});
    const [shown, setShown] = useState<Shown | null>(null);

    const publicKeyReading = inspectField('publicKey', publicKey, formats.publicKey);

    const verify = async (picked: FormatOverrides = formats) => {
        const found: { token?: string; publicKey?: string } = {};
        let parsed: ParsedJws | undefined;
        try {
            parsed = parseJws(token);
        } catch (error) {
            if (!(error instanceof JwsError)) throw error;
            found.token = error.message;
        }
        const key = new VerifyEd25519('', null, publicKey, null, undefined, picked);
        found.publicKey = key.validate(['publicKey']).publicKey;
        setChoices(key.choices(['publicKey']).publicKey);
        setErrors(found);
        if (!parsed || found.publicKey) {
            setShown(null);
            return;
        }
        const info = describePayload(parsed.payload);
        setShown({
            verdict: await verdictOf(parsed.signature, parsed.signingInput, key.bytesOf('publicKey')),
            parsed,
            info,
            notes: timeNotes(info, Math.floor(Date.now() / 1000)),
        });
    };

    const edit = (setter: (value: string) => void, field: 'token' | 'publicKey') => (value: string) => {
        setter(value);
        setShown(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
        if (field === 'publicKey') {
            setChoices(undefined);
            setFormats((current) => ({ ...current, publicKey: undefined }));
        }
    };

    return (
        <>
            <Field
                label="Token"
                rows={4}
                value={token}
                error={errors.token}
                placeholder="eyJhbGciOiJFZERTQSJ9.… (a JWS or a JWT signed with EdDSA)"
                onInput={edit(setToken, 'token')}
            />
            <Field
                label="Public key"
                rows={2}
                growWithContent
                value={publicKey}
                error={errors.publicKey}
                choices={choices}
                onChoose={(format) => {
                    const picked = { ...formats, publicKey: format };
                    setFormats(picked);
                    verify(picked);
                }}
                hint={readingHint(publicKeyReading)}
                placeholder="Hex, base64, PEM, OpenSSH or a JWK, such as {&quot;kty&quot;:&quot;OKP&quot;,&quot;crv&quot;:&quot;Ed25519&quot;,&quot;x&quot;:…}"
                fileKind="key"
                onInput={edit(setPublicKey, 'publicKey')}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={() => verify()}>
                    Verify
                </button>
            </div>
            {shown?.verdict === 'valid' && <Banner kind="success">Signature is valid</Banner>}
            {shown?.verdict === 'invalid' && <Banner kind="error">Signature is wrong</Banner>}
            {shown?.verdict === 'permissive-only' && (
                <Banner kind="warning">
                    Signature is not valid under the strict RFC 8032 rules, but it would be accepted under ZIP215, the more permissive rules
                    used by some systems (e.g. Zcash).
                </Banner>
            )}
            {shown && <Decoded shown={shown} />}
        </>
    );
}

const DEFAULT_HEADER = '{"alg":"EdDSA","typ":"JWT"}';

function Create() {
    const [privateKey, setPrivateKey] = useState('');
    const [header, setHeader] = useState(DEFAULT_HEADER);
    const [payload, setPayload] = useState('');
    const [revealed, setRevealed] = useState(false);
    const [errors, setErrors] = useState<{ privateKey?: string; header?: string }>({});
    const [result, setResult] = useState<{ token: string; jwk: string } | null>(null);

    const sign = async () => {
        const found: { privateKey?: string; header?: string } = {};
        try {
            checkHeaderToSign(header);
        } catch (error) {
            if (!(error instanceof JwsError)) throw error;
            found.header = error.message;
        }
        const input = signingInputOf(header, payload);
        const signer = new VerifyEd25519(bytesOfInput(input), null, null, privateKey);
        found.privateKey = signer.validate(['privateKey']).privateKey;
        setErrors(found);
        if (found.header || found.privateKey) {
            setResult(null);
            return;
        }
        try {
            const signature = await signer.signBytes();
            setResult({ token: tokenOf(input, signature), jwk: encodeJwk(await signer.getPublicKeyBytes()) });
        } catch (error) {
            setResult(null);
            if (!(error instanceof InputError)) throw error;
            setErrors({ privateKey: error.message });
        }
    };

    const clear = (setter: (value: string) => void, field: 'privateKey' | 'header') => (value: string) => {
        setter(value);
        setResult(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
    };

    return (
        <>
            <Field
                label="Private key"
                rows={2}
                growWithContent
                value={privateKey}
                error={errors.privateKey}
                placeholder="Hex, base64, PEM, OpenSSH or JWK"
                secret
                revealed={revealed}
                onRevealedChange={setRevealed}
                fileKind="key"
                onInput={clear(setPrivateKey, 'privateKey')}
            />
            <Field
                label="Header"
                rows={2}
                value={header}
                error={errors.header}
                hint={'It must say "alg": "EdDSA". It is signed exactly as you write it.'}
                onInput={clear(setHeader, 'header')}
            />
            <Field
                label="Payload"
                rows={4}
                value={payload}
                placeholder='{"sub":"1234567890","name":"Ada"} (JSON for a JWT, or any text)'
                onInput={(value) => {
                    setPayload(value);
                    setResult(null);
                }}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={sign}>
                    Sign
                </button>
            </div>
            {result && (
                <>
                    <Banner kind="success">
                        <div class="result-head">
                            <strong>Token:</strong>
                            <div class="field-actions">
                                <CopyButton text={result.token} label="Copy token" />
                                <DownloadButton filename="token.jwt" text={result.token} label="Download token" />
                            </div>
                        </div>
                        <div class="result">{result.token}</div>
                    </Banner>
                    <Field
                        label="Public key to verify it, as a JWK"
                        rows={3}
                        value={result.jwk}
                        copyable
                        disabled
                        download={{ filename: fileNameFor('public', 'jwk') }}
                    />
                </>
            )}
        </>
    );
}

/** Both stay mounted, so what was typed in one is still there after a look at the other. */
export default function JwsPanel({ mode }: { mode: 'verify' | 'create' }) {
    return (
        <>
            <div class="panel" hidden={mode !== 'verify'}>
                <Verify />
            </div>
            <div class="panel" hidden={mode !== 'create'}>
                <Create />
            </div>
        </>
    );
}
