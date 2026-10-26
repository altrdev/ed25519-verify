import { useEffect, useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import type { Hints } from './diagnose';
import { diagnose } from './diagnose';
import DownloadButton from './DownloadButton';
import { ExampleButton, ExampleNote, nextIndex } from './ExampleButton';
import { type JwsExample, JWS_EXAMPLES } from './examples';
import HintList from './HintList';
import { jwsShareFragment, type SharedToken } from './share';
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
import { looksLikeDidDocument, parseDidDocument } from './did';
import { JwksError, keyChoiceLabel, looksLikeJwkSet, parseJwkSet, selectKey, type SetKey } from './jwks';
import { encodeJwk } from './keyfiles';
import { readingHint } from './FormatMenu';
import type { RawFormat } from './enum';
import { MessageFormat } from './enum';
import VerifyEd25519, { inspectField, type FormatOverrides, InputError, type Verdict, verdictOf } from './signature';
import Results from './Results';
import Checks from './Checks';
import { VerdictPill, VerdictScope, VerifyButton } from './Verdict';

interface Shown {
    verdict: Verdict;
    publicKey: Uint8Array;
    hints?: Hints;
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

function Verify({ initial, autoVerify }: { initial?: Partial<SharedToken>; autoVerify?: boolean }) {
    const [token, setToken] = useState(initial?.token ?? '');
    const [publicKey, setPublicKey] = useState(initial?.publicKey ?? '');
    const [exampleIndex, setExampleIndex] = useState<number | null>(null);
    const [errors, setErrors] = useState<{ token?: string; publicKey?: string }>({});
    const [choices, setChoices] = useState<RawFormat[] | undefined>(undefined);
    const [formats, setFormats] = useState<FormatOverrides>({});
    const [shown, setShown] = useState<Shown | null>(null);
    const [keyNote, setKeyNote] = useState<string | undefined>(undefined);
    const [keyOptions, setKeyOptions] = useState<SetKey[] | undefined>(undefined);

    const isSet = looksLikeJwkSet(publicKey) || looksLikeDidDocument(publicKey);
    const publicKeyReading = isSet ? null : inspectField('publicKey', publicKey, formats.publicKey);

    const verify = async (picked: FormatOverrides = formats, values = { token, publicKey }, chosen?: number) => {
        const found: { token?: string; publicKey?: string } = {};
        let parsed: ParsedJws | undefined;
        try {
            parsed = parseJws(values.token);
        } catch (error) {
            if (!(error instanceof JwsError)) throw error;
            found.token = error.message;
        }
        let publicKeyBytes: Uint8Array | undefined;
        let note: string | undefined;
        let options: SetKey[] | undefined;
        if (looksLikeJwkSet(values.publicKey) || looksLikeDidDocument(values.publicKey)) {
            // a set of keys (or a DID document): the one the token names, from the set the user pasted (never a key carried by the token)
            setChoices(undefined);
            try {
                const set = looksLikeDidDocument(values.publicKey) ? parseDidDocument(values.publicKey) : parseJwkSet(values.publicKey);
                if (parsed) {
                    const selection = selectKey(set, parsed.header.kid, chosen);
                    if ('key' in selection) {
                        publicKeyBytes = selection.key.publicKey;
                        note = selection.note;
                    } else {
                        found.publicKey = selection.error;
                        if ('choose' in selection) options = selection.choose;
                    }
                }
            } catch (error) {
                if (!(error instanceof JwksError)) throw error;
                found.publicKey = error.message;
            }
        } else {
            const key = new VerifyEd25519('', null, values.publicKey, null, undefined, picked);
            found.publicKey = key.validate(['publicKey']).publicKey;
            setChoices(key.choices(['publicKey']).publicKey);
            if (!found.publicKey) publicKeyBytes = key.bytesOf('publicKey');
        }
        setKeyNote(note);
        setKeyOptions(options);
        setErrors(found);
        if (!parsed || found.publicKey || !publicKeyBytes) {
            setShown(null);
            return;
        }
        const info = describePayload(parsed.payload);
        const verdict = await verdictOf(parsed.signature, parsed.signingInput, publicKeyBytes);
        setShown({
            verdict,
            publicKey: publicKeyBytes,
            // what usually explains a wrong signature, when one of those makes it valid (the signed bytes are the signing input)
            hints:
                verdict === 'invalid'
                    ? await diagnose(
                          {
                              publicKey: publicKeyBytes,
                              signature: parsed.signature,
                              message: parsed.signingInput,
                              messageFormat: MessageFormat.Text,
                              skipHashes: true,
                          },
                          parsed.signingInput,
                      )
                    : undefined,
            parsed,
            info,
            notes: timeNotes(info, Math.floor(Date.now() / 1000)),
        });
    };

    // a share link: the answer is the first thing the reader sees
    useEffect(() => {
        if (autoVerify && token && publicKey) verify();
    }, []);

    const loadExample = (example: JwsExample) => {
        setToken(example.token);
        setPublicKey(example.publicKey);
        setErrors({});
        setChoices(undefined);
        setFormats({});
        setKeyOptions(undefined);
        verify({}, example);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, JWS_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(JWS_EXAMPLES[index]);
    };

    const link = () => `${location.origin}${location.pathname}${location.search}${jwsShareFragment({ token, publicKey })}`;
    const shareable = jwsShareFragment({ token, publicKey }) !== '';

    const edit = (setter: (value: string) => void, field: 'token' | 'publicKey') => (value: string) => {
        setter(value);
        setShown(null);
        setKeyNote(undefined);
        setKeyOptions(undefined);
        setErrors((current) => ({ ...current, [field]: undefined }));
        if (field === 'publicKey') {
            setChoices(undefined);
            setFormats((current) => ({ ...current, publicKey: undefined }));
        }
    };

    return (
        <VerdictScope>
            <Field
                label="Token"
                rows={4}
                value={token}
                error={errors.token}
                placeholder="eyJhbGciOiJFZERTQSJ9.… (a JWS or a JWT signed with EdDSA)"
                fileKind="text"
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
                picks={keyOptions?.map((key) => ({ label: keyChoiceLabel(key), onPick: () => verify(formats, undefined, key.position) }))}
                hint={isSet ? keyNote : readingHint(publicKeyReading)}
                placeholder="Hex, base64, PEM, OpenSSH, a JWK such as {&quot;kty&quot;:&quot;OKP&quot;,&quot;crv&quot;:&quot;Ed25519&quot;,&quot;x&quot;:…} a whole JWK Set or a DID document (the key is picked by the kid of the token)"
                fileKind="key"
                onInput={edit(setPublicKey, 'publicKey')}
            />
            <div class="actions">
                <VerifyButton onClick={() => verify()} />
                <VerdictPill />
                <CopyButton text={shareable ? link() : ''} label="Copy link to this verification" caption="Copy link" />
                <ExampleButton onClick={loadNextExample} />
            </div>
            <Results>
                <ExampleNote example={exampleIndex === null ? null : JWS_EXAMPLES[exampleIndex]} />
                {shown?.verdict === 'valid' && (
                    <Banner kind="success" stamp pill="Valid">
                        Signature is valid
                    </Banner>
                )}
                {shown?.verdict === 'invalid' && (
                    <Banner kind="error" stamp pill="Wrong">
                        Signature is wrong
                    </Banner>
                )}
                {shown?.verdict === 'invalid' && shown.hints && <HintList hints={shown.hints} />}
                {shown?.verdict === 'permissive-only' && (
                    <Banner kind="warning" pill="ZIP215 only">
                        Signature is not valid under the strict RFC 8032 rules, but it would be accepted under ZIP215, the more permissive
                        rules used by some systems (e.g. Zcash).
                    </Banner>
                )}
                {shown && <Checks signature={shown.parsed.signature} publicKey={shown.publicKey} verdict={shown.verdict} />}
                {shown && <Decoded shown={shown} />}
            </Results>
        </VerdictScope>
    );
}

const DEFAULT_HEADER = '{"alg":"EdDSA","typ":"JWT"}';

function Create() {
    const [exampleIndex, setExampleIndex] = useState<number | null>(null);
    const [published, setPublished] = useState<string | null>(null);
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

    const loadExample = (example: JwsExample) => {
        setPrivateKey(example.privateKey);
        setHeader(example.header);
        setPayload(example.payload);
        setRevealed(true);
        setErrors({});
        setResult(null);
        setPublished(example.token);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, JWS_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(JWS_EXAMPLES[index]);
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
                <ExampleButton onClick={loadNextExample} />
            </div>
            <Results>
                <ExampleNote example={exampleIndex === null ? null : JWS_EXAMPLES[exampleIndex]} />
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
                            {published === result.token && <p>Identical to the token of the example.</p>}
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
            </Results>
        </>
    );
}

/** Both stay mounted, so what was typed in one is still there after a look at the other. */
export default function JwsPanel({
    mode,
    initial,
    autoVerify,
}: {
    mode: 'verify' | 'create';
    initial?: Partial<SharedToken>;
    autoVerify?: boolean;
}) {
    return (
        <>
            <div class="panel" hidden={mode !== 'verify'}>
                <Verify initial={initial} autoVerify={autoVerify} />
            </div>
            <div class="panel" hidden={mode !== 'create'}>
                <Create />
            </div>
        </>
    );
}
