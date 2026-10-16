import { useEffect, useState } from 'preact/hooks';
import * as ed from '@noble/ed25519';
import Banner from './Banner';
import { bytesToBase64, bytesToHex } from './bytes';
import type { CborKey, CborValue } from './cbor';
import { isBytes } from './cbor';
import {
    bytesFromText,
    CoseError,
    encodeCoseKey,
    HEADER_NAMES,
    type Header,
    type ParsedCose,
    parseCose,
    readCoseKey,
    signCose,
    signedData,
} from './cose';
import CopyButton from './CopyButton';
import { type Hints, diagnose } from './diagnose';
import DownloadButton from './DownloadButton';
import { ExampleButton, ExampleNote, nextIndex } from './ExampleButton';
import { MessageFormat, type RawFormat } from './enum';
import { COSE_EXAMPLES, type CoseExample } from './examples';
import Field from './Field';
import { readingHint } from './FormatMenu';
import HintList from './HintList';
import MessageField from './MessageField';
import type { MessageFile } from './messagefile';
import Segmented from './Segmented';
import { coseShareFragment, type SharedCose } from './share';
import VerifyEd25519, { type FormatOverrides, inspectField, type Verdict, verdictOf } from './signature';

type Errors = Partial<Record<'message' | 'publicKey' | 'payload' | 'privateKey' | 'kid' | 'contentType', string>>;

const encoder = new TextEncoder();
const asError = (error: unknown) => {
    if (error instanceof CoseError) return error.message;
    throw error;
};

interface Shown {
    verdict: Verdict;
    parsed: ParsedCose;
    /** where the payload came from, and how big it is */
    payloadBytes: Uint8Array;
    attached: boolean;
    hints?: Hints;
}

const printable = (bytes: Uint8Array) => {
    try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        // biome-ignore lint/suspicious/noControlCharactersInRegex: this is exactly what is being looked for
        return /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text) ? null : text;
    } catch {
        return null;
    }
};
const clip = (text: string, length = 200) => (text.length > length ? `${text.slice(0, length)}…` : text);

/** A header value for a person: bytes as text when they are text, else as hex. */
function showValue(value: CborValue): string {
    if (isBytes(value))
        return printable(value) !== null && value.length ? clip(`"${printable(value)}"`) : `h'${clip(bytesToHex(value), 80)}'`;
    if (typeof value === 'string') return clip(`"${value}"`);
    if (Array.isArray(value)) return `[${value.map(showValue).join(', ')}]`;
    if (value instanceof Map) return `{${Array.from(value, ([k, v]) => `${k}: ${showValue(v)}`).join(', ')}}`;
    return String(value && typeof value === 'object' ? 'tag' : value);
}

const label = (key: CborKey) => (typeof key === 'number' && HEADER_NAMES[key] ? `${HEADER_NAMES[key]} (${key})` : String(key));

function HeaderList({ title, header, note }: { title: string; header: Header; note: string }) {
    return (
        <li>
            {title} <span class="muted">({note})</span>
            {header.size === 0 ? (
                ': empty'
            ) : (
                <ul>
                    {Array.from(header, ([key, value]) => (
                        <li key={String(key)}>
                            {label(key)}: {showValue(value)}
                        </li>
                    ))}
                </ul>
            )}
        </li>
    );
}

const bytesLabel = (size: number) => `${size.toLocaleString('en-US')} byte${size === 1 ? '' : 's'}`;

function Details({ shown }: { shown: Shown }) {
    const { parsed } = shown;
    const text = printable(shown.payloadBytes);
    return (
        <section class="decoded" aria-label="Message details">
            <h2>What the message says</h2>
            <ul>
                <li>
                    {parsed.cwt
                        ? 'A CWT (tag 61) holding a COSE_Sign1'
                        : parsed.tagged
                          ? 'COSE_Sign1 (tag 18)'
                          : 'COSE_Sign1 without a tag'}
                    , algorithm {parsed.algorithm === -19 ? 'Ed25519 (-19)' : 'EdDSA (-8)'}
                </li>
                <HeaderList title="Protected header" header={parsed.protectedHeader} note="signed" />
                <HeaderList title="Unprotected header" header={parsed.unprotectedHeader} note="not signed: anyone could have changed it" />
                <li>
                    Payload ({shown.attached ? 'in the message' : 'given apart'}, {bytesLabel(shown.payloadBytes.length)}):{' '}
                    {text !== null ? <code>{clip(text)}</code> : <code>{clip(bytesToHex(shown.payloadBytes), 120)}</code>}
                </li>
            </ul>
        </section>
    );
}

function Verify({
    initial,
    initialFile,
    autoVerify,
}: {
    initial?: Partial<SharedCose>;
    initialFile?: MessageFile | null;
    autoVerify?: boolean;
}) {
    const [message, setMessage] = useState(initial?.message ?? '');
    const [publicKey, setPublicKey] = useState(initial?.publicKey ?? '');
    const [payload, setPayload] = useState(initial?.payload ?? '');
    const [payloadFormat, setPayloadFormat] = useState(initial?.payloadFormat ?? MessageFormat.Text);
    const [externalData, setExternalData] = useState(initial?.externalData ?? '');
    const [file, setFile] = useState<MessageFile | null>(initialFile ?? null);
    const [errors, setErrors] = useState<Errors>({});
    const [choices, setChoices] = useState<RawFormat[] | undefined>(undefined);
    const [formats, setFormats] = useState<FormatOverrides>({});
    const [shown, setShown] = useState<Shown | null>(null);
    const [exampleIndex, setExampleIndex] = useState<number | null>(null);

    const coseKey = readCoseKey(publicKey);
    const publicKeyReading = coseKey ? null : inspectField('publicKey', publicKey, formats.publicKey);

    const verify = async (
        picked: FormatOverrides = formats,
        values = { message, publicKey, payload, payloadFormat, externalData, file },
    ) => {
        const found: Errors = {};
        let parsed: ParsedCose | undefined;
        try {
            parsed = parseCose(bytesFromText(values.message));
        } catch (error) {
            found.message = asError(error);
        }

        let key: Uint8Array | undefined;
        let keyId: Uint8Array | undefined;
        if (!values.publicKey.trim()) {
            found.publicKey = 'The public key is needed: a COSE message does not carry it.';
            setChoices(undefined);
        } else {
            const fromCose = readCoseKey(values.publicKey);
            if (fromCose) {
                if (fromCose.publicKey) key = fromCose.publicKey;
                else found.publicKey = 'This COSE_Key holds only a private key: give the public one.';
                keyId = fromCose.kid;
                setChoices(undefined);
            } else {
                const reader = new VerifyEd25519('', null, values.publicKey, null, undefined, picked);
                found.publicKey = reader.validate(['publicKey']).publicKey;
                setChoices(reader.choices(['publicKey']).publicKey);
                if (!found.publicKey) key = reader.bytesOf('publicKey');
            }
        }

        // the payload: in the message, or given apart
        const given = values.file?.bytes ?? values.payload;
        const reader = new VerifyEd25519(given, null, null, null, values.payloadFormat);
        let payloadBytes: Uint8Array | undefined;
        if (parsed?.payload) {
            payloadBytes = parsed.payload;
        } else if (parsed) {
            if (!values.file && !values.payload) {
                found.payload = 'This message has its payload apart (nil): give it here.';
            } else {
                found.payload = reader.validate(['message']).message;
                if (!found.payload) payloadBytes = reader.messageBytes();
            }
        }

        const messageKid = parsed && (parsed.protectedHeader.get(4) ?? parsed.unprotectedHeader.get(4));
        if (isBytes(messageKid) && keyId && bytesToHex(messageKid) !== bytesToHex(keyId)) {
            found.publicKey = `The message names the key ${showValue(messageKid)}, the key you gave is ${showValue(keyId)}.`;
        }

        setErrors(found);
        if (!parsed || !key || !payloadBytes || found.publicKey || found.payload) {
            setShown(null);
            return;
        }
        const aad = encoder.encode(values.externalData);
        const verdict = await verdictOf(parsed.signature, signedData(parsed.protectedBytes, payloadBytes, aad), key);
        setShown({
            verdict,
            parsed,
            payloadBytes,
            attached: !!parsed.payload,
            // the usual mistakes about a payload given apart, tried through what is really signed
            hints:
                verdict === 'invalid'
                    ? await diagnose(
                          {
                              publicKey: key,
                              signature: parsed.signature,
                              message: parsed.payload ? payloadBytes : given,
                              messageFormat: values.payloadFormat,
                              skipHashes: true,
                              frame: async (candidate) => signedData((parsed as ParsedCose).protectedBytes, candidate, aad),
                          },
                          payloadBytes,
                      )
                    : undefined,
        });
    };

    // a share link: the answer is the first thing the reader sees
    useEffect(() => {
        if (autoVerify && message && publicKey) verify();
    }, []);

    const reset = (field: keyof Errors) => {
        setShown(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
    };

    const loadExample = (example: CoseExample) => {
        const values = {
            message: example.message,
            publicKey: example.publicKey,
            payload: example.detached ? example.payload : '',
            payloadFormat: MessageFormat.Text,
            externalData: example.externalData,
            file: null,
        };
        setMessage(values.message);
        setPublicKey(values.publicKey);
        setPayload(values.payload);
        setPayloadFormat(MessageFormat.Text);
        setExternalData(values.externalData);
        setFile(null);
        setErrors({});
        setChoices(undefined);
        setFormats({});
        verify({}, values);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, COSE_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(COSE_EXAMPLES[index]);
    };

    const fragment = coseShareFragment({ message, publicKey, payload: file ? '' : payload, payloadFormat, externalData });
    const shareable = fragment !== '' && !file;
    const link = () => `${location.origin}${location.pathname}${location.search}${fragment}`;

    return (
        <>
            <Field
                label="COSE message"
                rows={4}
                value={message}
                error={errors.message}
                placeholder="D2 84 43 A1 01 27 … (hex or base64 of the COSE_Sign1)"
                fileKind="binary"
                onInput={(value) => {
                    setMessage(value);
                    reset('message');
                }}
            />
            <MessageField
                label="Payload"
                hint="Only if the message does not hold it (its payload is nil)."
                value={payload}
                onInput={(value) => {
                    setPayload(value);
                    reset('payload');
                }}
                format={payloadFormat}
                onFormatChange={(format) => {
                    setPayloadFormat(format);
                    reset('payload');
                }}
                error={errors.payload}
                file={file}
                onFile={(chosen) => {
                    setFile(chosen);
                    reset('payload');
                }}
                onFileError={(error) => setErrors((current) => ({ ...current, payload: error }))}
            />
            <Field
                label="External data (optional)"
                rows={1}
                value={externalData}
                hint="Text that the signer covered but the message does not carry (external_aad). Empty almost always."
                onInput={(value) => {
                    setExternalData(value);
                    reset('message');
                }}
            />
            <Field
                label="Public key you trust"
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
                hint={coseKey ? 'COSE_Key (Ed25519)' : readingHint(publicKeyReading)}
                placeholder="Hex, base64, PEM, OpenSSH, JWK, or a COSE_Key in hex or base64"
                fileKind="key"
                onInput={(value) => {
                    setPublicKey(value);
                    reset('publicKey');
                    setChoices(undefined);
                    setFormats((current) => ({ ...current, publicKey: undefined }));
                }}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={() => verify()}>
                    Verify
                </button>
                <CopyButton text={shareable ? link() : ''} label="Copy link to this verification" caption="Copy link" />
                <ExampleButton onClick={loadNextExample} />
            </div>
            <ExampleNote example={exampleIndex === null ? null : COSE_EXAMPLES[exampleIndex]} />
            {shown?.verdict === 'valid' && <Banner kind="success">Signature is valid</Banner>}
            {shown?.verdict === 'invalid' && <Banner kind="error">Signature is wrong</Banner>}
            {shown?.verdict === 'invalid' && shown.hints && <HintList hints={shown.hints} />}
            {shown?.verdict === 'permissive-only' && (
                <Banner kind="warning">
                    Signature is not valid under the strict RFC 8032 rules, but it would be accepted under ZIP215, the more permissive rules
                    used by some systems (e.g. Zcash).
                </Banner>
            )}
            {shown && <Details shown={shown} />}
        </>
    );
}

function Create() {
    const [exampleIndex, setExampleIndex] = useState<number | null>(null);
    const [published, setPublished] = useState<string | null>(null);
    const [privateKey, setPrivateKey] = useState('');
    const [revealed, setRevealed] = useState(false);
    const [payload, setPayload] = useState('');
    const [payloadFormat, setPayloadFormat] = useState(MessageFormat.Text);
    const [file, setFile] = useState<MessageFile | null>(null);
    const [kid, setKid] = useState('');
    const [contentType, setContentType] = useState('');
    const [externalData, setExternalData] = useState('');
    const [detached, setDetached] = useState<'included' | 'apart'>('included');
    const [tagged, setTagged] = useState<'tag' | 'none'>('tag');
    const [shownAs, setShownAs] = useState<'hex' | 'base64'>('hex');
    const [errors, setErrors] = useState<Errors>({});
    const [result, setResult] = useState<{ bytes: Uint8Array; publicKey: Uint8Array } | null>(null);

    const sign = async () => {
        const found: Errors = {};
        let type: number | string | undefined;
        const trimmed = contentType.trim();
        if (trimmed) type = /^\d+$/.test(trimmed) && Number(trimmed) < 65536 ? Number(trimmed) : trimmed;
        if (typeof type === 'string' && !/^[\w.+-]+\/[\w.+-]+$/.test(type)) {
            found.contentType = 'A content type is a number (a CoAP content format) or a media type such as application/json.';
        }
        const signer = new VerifyEd25519(file?.bytes ?? payload, null, null, privateKey, payloadFormat);
        const fields = signer.validate(['privateKey', 'message']);
        found.privateKey = fields.privateKey;
        found.payload = fields.message;
        setErrors(found);
        if (found.contentType || found.privateKey || found.payload) {
            setResult(null);
            return;
        }
        const seed = (await signer.bytesOf('privateKey')).slice(0, 32);
        const bytes = await signCose(signer.messageBytes(), seed, {
            kid: kid ? encoder.encode(kid) : undefined,
            contentType: type,
            externalAad: encoder.encode(externalData),
            detached: detached === 'apart',
            tagged: tagged === 'tag',
        });
        setResult({ bytes, publicKey: await ed.getPublicKeyAsync(seed) });
    };

    const clear = (field: keyof Errors) => {
        setResult(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
    };

    const loadExample = (example: CoseExample) => {
        setPrivateKey(example.privateKey);
        setPayload(example.payload);
        setPayloadFormat(MessageFormat.Text);
        setFile(null);
        setKid(example.kid);
        setContentType(example.contentType);
        setExternalData(example.externalData);
        setDetached(example.detached ? 'apart' : 'included');
        setTagged('tag');
        setRevealed(true);
        setErrors({});
        setResult(null);
        setPublished(example.message);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, COSE_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(COSE_EXAMPLES[index]);
    };

    const written = result ? (shownAs === 'hex' ? bytesToHex(result.bytes) : bytesToBase64(result.bytes)) : '';

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
                onInput={(value) => {
                    setPrivateKey(value);
                    clear('privateKey');
                }}
            />
            <MessageField
                label="Payload"
                value={payload}
                onInput={(value) => {
                    setPayload(value);
                    clear('payload');
                }}
                format={payloadFormat}
                onFormatChange={(format) => {
                    setPayloadFormat(format);
                    clear('payload');
                }}
                error={errors.payload}
                file={file}
                onFile={(chosen) => {
                    setFile(chosen);
                    clear('payload');
                }}
                onFileError={(error) => setErrors((current) => ({ ...current, payload: error }))}
            />
            <Field
                label="Key ID (optional)"
                rows={1}
                value={kid}
                hint="The name of the key, written in the unprotected header (kid, label 4) for whoever picks the key to verify with."
                onInput={(value) => {
                    setKid(value);
                    clear('kid');
                }}
            />
            <Field
                label="Content type (optional)"
                rows={1}
                value={contentType}
                error={errors.contentType}
                placeholder="application/json, or a number such as 50"
                hint="Written in the protected header (label 3), so it is signed."
                onInput={(value) => {
                    setContentType(value);
                    clear('contentType');
                }}
            />
            <Field
                label="External data (optional)"
                rows={1}
                value={externalData}
                hint="Text that the signature covers but the message does not carry (external_aad). Whoever verifies must give the same."
                onInput={(value) => {
                    setExternalData(value);
                    clear('payload');
                }}
            />
            <div class="mode-row">
                <Segmented
                    label="Payload in the message"
                    value={detached}
                    onChange={(value) => {
                        setDetached(value);
                        setResult(null);
                    }}
                    options={[
                        { value: 'included', label: 'Included' },
                        { value: 'apart', label: 'Apart (nil)' },
                    ]}
                />
                <Segmented
                    label="Tag"
                    value={tagged}
                    onChange={(value) => {
                        setTagged(value);
                        setResult(null);
                    }}
                    options={[
                        { value: 'tag', label: 'COSE_Sign1 (tag 18)' },
                        { value: 'none', label: 'No tag' },
                    ]}
                />
            </div>
            <div class="actions">
                <button type="button" class="primary" onClick={sign}>
                    Sign
                </button>
                <ExampleButton onClick={loadNextExample} />
            </div>
            <ExampleNote example={exampleIndex === null ? null : COSE_EXAMPLES[exampleIndex]} />
            {result && (
                <>
                    <Banner kind="success">
                        <div class="result-head">
                            <strong>COSE_Sign1:</strong>
                            <div class="field-actions">
                                <Segmented
                                    label="Show the message as"
                                    value={shownAs}
                                    onChange={setShownAs}
                                    options={[
                                        { value: 'hex', label: 'Hex' },
                                        { value: 'base64', label: 'Base64' },
                                    ]}
                                />
                                <CopyButton text={written} label="Copy message" />
                                <DownloadButton filename="message.cose" text="" bytes={result.bytes} label="Download message" />
                            </div>
                        </div>
                        <div class="result">{written}</div>
                        {published === bytesToHex(result.bytes) && <p>Identical to the message of the example.</p>}
                    </Banner>
                    <Field
                        label="Public key to verify it (COSE_Key)"
                        rows={2}
                        value={bytesToHex(encodeCoseKey(result.publicKey, kid ? encoder.encode(kid) : undefined))}
                        copyable
                        disabled
                        hint="The public key as a COSE_Key; the same key as a plain 32-byte key also works in the Verify tab."
                    />
                </>
            )}
        </>
    );
}

/** Both stay mounted, so what was typed in one is still there after a look at the other. */
export default function CosePanel({
    mode,
    initial,
    initialFile,
    autoVerify,
}: {
    mode: 'verify' | 'create';
    initial?: Partial<SharedCose>;
    initialFile?: MessageFile | null;
    autoVerify?: boolean;
}) {
    return (
        <>
            <div class="panel" hidden={mode !== 'verify'}>
                <Verify initial={initial} initialFile={initialFile} autoVerify={autoVerify} />
            </div>
            <div class="panel" hidden={mode !== 'create'}>
                <Create />
            </div>
        </>
    );
}
