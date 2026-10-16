import { useEffect, useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import { type Hints, diagnose } from './diagnose';
import DownloadButton from './DownloadButton';
import { ExampleButton, ExampleNote, nextIndex } from './ExampleButton';
import { MessageFormat, type RawFormat } from './enum';
import { MINISIGN_EXAMPLES, type MinisignExample } from './examples';
import Field from './Field';
import { readingHint } from './FormatMenu';
import HintList from './HintList';
import {
    commentSignedBytes,
    keyIdText,
    looksLikeMinisignPublic,
    MinisignError,
    type MinisignPublic,
    type ParsedMinisign,
    parseKeyId,
    parseMinisign,
    parseMinisignPublic,
    signedBytes,
    signMinisign,
} from './minisign';
import MessageField from './MessageField';
import type { MessageFile } from './messagefile';
import { minisignShareFragment, type SharedMinisign } from './share';
import VerifyEd25519, { type FormatOverrides, inspectField, type Verdict, verdictOf } from './signature';

type Errors = Partial<Record<'signature' | 'publicKey' | 'message' | 'privateKey' | 'keyId' | 'comment', string>>;

const asError = (error: unknown) => {
    if (error instanceof MinisignError) return error.message;
    throw error;
};

interface Shown {
    verdict: Verdict;
    parsed: ParsedMinisign;
    /** the signature of the trusted comment is valid: the comment is the one that was signed */
    commentOk: boolean;
    size: number;
    hints?: Hints;
}

const bytesLabel = (size: number) => `${size.toLocaleString('en-US')} byte${size === 1 ? '' : 's'}`;

function Details({ shown }: { shown: Shown }) {
    const { parsed } = shown;
    return (
        <section class="decoded" aria-label="Signature details">
            <h2>What the signature says</h2>
            <ul>
                <li>
                    Key ID: <strong>{keyIdText(parsed.keyId)}</strong>
                </li>
                <li>
                    {parsed.algorithm === 'ED'
                        ? 'Form: ED, it signs the BLAKE2b-512 hash of the message (what minisign writes by default)'
                        : 'Form: Ed (legacy), it signs the message itself'}
                </li>
                <li>Message: {bytesLabel(shown.size)}</li>
                {shown.commentOk ? (
                    <li>Trusted comment (signed, so it is authentic): {parsed.trustedComment || '(empty)'}</li>
                ) : (
                    <li>Trusted comment (its signature does not match, do not rely on it): {parsed.trustedComment || '(empty)'}</li>
                )}
                <li>Untrusted comment (not signed, anyone could have written it): {parsed.untrustedComment || '(empty)'}</li>
            </ul>
        </section>
    );
}

function Verify({
    initial,
    initialFile,
    autoVerify,
}: {
    initial?: Partial<SharedMinisign>;
    initialFile?: MessageFile | null;
    autoVerify?: boolean;
}) {
    const [signature, setSignature] = useState(initial?.signature ?? '');
    const [publicKey, setPublicKey] = useState(initial?.publicKey ?? '');
    const [message, setMessage] = useState(initial?.message ?? '');
    const [messageFormat, setMessageFormat] = useState(initial?.messageFormat ?? MessageFormat.Text);
    const [file, setFile] = useState<MessageFile | null>(initialFile ?? null);
    const [errors, setErrors] = useState<Errors>({});
    const [choices, setChoices] = useState<RawFormat[] | undefined>(undefined);
    const [formats, setFormats] = useState<FormatOverrides>({});
    const [shown, setShown] = useState<Shown | null>(null);
    const [exampleIndex, setExampleIndex] = useState<number | null>(null);

    const isMinisignKey = looksLikeMinisignPublic(publicKey);
    const publicKeyReading = isMinisignKey ? null : inspectField('publicKey', publicKey, formats.publicKey);
    const minisignKey = (() => {
        try {
            return isMinisignKey ? parseMinisignPublic(publicKey) : null;
        } catch {
            return null;
        }
    })();

    const verify = async (picked: FormatOverrides = formats, values = { signature, publicKey, message, messageFormat, file }) => {
        const found: Errors = {};
        let parsed: ParsedMinisign | undefined;
        try {
            parsed = parseMinisign(values.signature);
        } catch (error) {
            found.signature = asError(error);
        }

        let key: Uint8Array | undefined;
        let identified: MinisignPublic | undefined;
        if (!values.publicKey.trim()) {
            found.publicKey = 'The public key is needed: a minisign signature does not carry it, only the ID of the key that made it.';
            setChoices(undefined);
        } else if (looksLikeMinisignPublic(values.publicKey)) {
            identified = parseMinisignPublic(values.publicKey);
            key = identified.publicKey;
            setChoices(undefined);
        } else {
            const reader = new VerifyEd25519('', null, values.publicKey, null, undefined, picked);
            found.publicKey = reader.validate(['publicKey']).publicKey;
            setChoices(reader.choices(['publicKey']).publicKey);
            if (!found.publicKey) key = reader.bytesOf('publicKey');
        }

        const given = values.file?.bytes ?? values.message;
        const messageReader = new VerifyEd25519(given, null, null, null, values.messageFormat);
        found.message = messageReader.validate(['message']).message;

        if (parsed && identified && keyIdText(parsed.keyId) !== keyIdText(identified.keyId)) {
            found.publicKey = `This signature was made by the key ${keyIdText(parsed.keyId)}, not by the key you gave (${keyIdText(identified.keyId)}).`;
        }

        setErrors(found);
        if (!parsed || !key || found.publicKey || found.message) {
            setShown(null);
            return;
        }
        const bytes = messageReader.messageBytes();
        const verdict = await verdictOf(parsed.signature, signedBytes(parsed.algorithm, bytes), key);
        const commentOk =
            (await verdictOf(parsed.globalSignature, commentSignedBytes(parsed.signature, parsed.trustedComment), key)) === 'valid';
        setShown({
            verdict,
            parsed,
            commentOk,
            size: bytes.length,
            // the usual mistakes about the message, tried through what is really signed (its hash, for the usual form)
            hints:
                verdict === 'invalid'
                    ? await diagnose(
                          {
                              publicKey: key,
                              signature: parsed.signature,
                              message: given,
                              messageFormat: values.messageFormat,
                              skipHashes: true,
                              frame: async (candidate) => signedBytes(parsed.algorithm, candidate),
                          },
                          bytes,
                      )
                    : undefined,
        });
    };

    // a share link: the answer is the first thing the reader sees
    useEffect(() => {
        if (autoVerify && signature && (message || publicKey)) verify();
    }, []);

    const reset = (field: keyof Errors) => {
        setShown(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
    };

    const loadExample = (example: MinisignExample) => {
        const values = {
            signature: example.signature,
            publicKey: example.publicKey,
            message: example.message,
            messageFormat: MessageFormat.Text,
            file: null,
        };
        setSignature(values.signature);
        setPublicKey(values.publicKey);
        setMessage(values.message);
        setMessageFormat(MessageFormat.Text);
        setFile(null);
        setErrors({});
        setChoices(undefined);
        setFormats({});
        verify({}, values);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, MINISIGN_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(MINISIGN_EXAMPLES[index]);
    };

    const fragment = minisignShareFragment({ signature, publicKey, message: file ? '' : message, messageFormat });
    const shareable = fragment !== '' && !file;
    const link = () => `${location.origin}${location.pathname}${location.search}${fragment}`;

    return (
        <>
            <Field
                label="Signature"
                rows={4}
                value={signature}
                error={errors.signature}
                placeholder="untrusted comment: … (the content of the .minisig file)"
                fileKind="text"
                onInput={(value) => {
                    setSignature(value);
                    reset('signature');
                }}
            />
            <MessageField
                value={message}
                onInput={(value) => {
                    setMessage(value);
                    reset('message');
                }}
                format={messageFormat}
                onFormatChange={(format) => {
                    setMessageFormat(format);
                    reset('message');
                }}
                error={errors.message}
                file={file}
                onFile={(chosen) => {
                    setFile(chosen);
                    reset('message');
                }}
                onFileError={(error) => setErrors((current) => ({ ...current, message: error }))}
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
                hint={minisignKey ? `minisign public key, ID ${keyIdText(minisignKey.keyId)}` : readingHint(publicKeyReading)}
                placeholder="RWQ… (the minisign .pub file, or its second line), or a public key in any other format"
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
            <ExampleNote example={exampleIndex === null ? null : MINISIGN_EXAMPLES[exampleIndex]} />
            {shown?.verdict === 'valid' && shown.commentOk && <Banner kind="success">Signature is valid</Banner>}
            {shown?.verdict === 'valid' && !shown.commentOk && (
                <Banner kind="error">
                    The signature of the message is valid, but the trusted comment is not the one that was signed: it was changed, or it
                    belongs to another signature. minisign refuses such a file.
                </Banner>
            )}
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
    const [comment, setComment] = useState('');
    const [keyId, setKeyId] = useState('');
    const [message, setMessage] = useState('');
    const [messageFormat, setMessageFormat] = useState(MessageFormat.Text);
    const [file, setFile] = useState<MessageFile | null>(null);
    const [errors, setErrors] = useState<Errors>({});
    const [result, setResult] = useState<{ armored: string; publicFile: string; keyId: string } | null>(null);

    const sign = async () => {
        const found: Errors = {};
        let id: Uint8Array | undefined;
        try {
            if (keyId.trim()) id = parseKeyId(keyId);
        } catch (error) {
            found.keyId = asError(error);
        }
        if (/[\r\n]/.test(comment)) found.comment = 'The trusted comment is one line: it cannot contain line breaks.';
        const signer = new VerifyEd25519(file?.bytes ?? message, null, null, privateKey, messageFormat);
        const fields = signer.validate(['privateKey', 'message']);
        found.privateKey = fields.privateKey;
        found.message = fields.message;
        setErrors(found);
        if (found.keyId || found.comment || found.privateKey || found.message) {
            setResult(null);
            return;
        }
        const seed = (await signer.bytesOf('privateKey')).slice(0, 32);
        const made = await signMinisign(signer.messageBytes(), seed, { trustedComment: comment, keyId: id });
        setResult({ armored: made.armored, publicFile: made.publicFile, keyId: keyIdText(made.keyId) });
    };

    const clear = (field: keyof Errors) => {
        setResult(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
    };

    const loadExample = (example: MinisignExample) => {
        setPrivateKey(example.privateKey);
        setComment(example.trustedComment);
        setKeyId(example.keyId);
        setMessage(example.message);
        setMessageFormat(MessageFormat.Text);
        setFile(null);
        setRevealed(true);
        setErrors({});
        setResult(null);
        setPublished(example.signature);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, MINISIGN_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(MINISIGN_EXAMPLES[index]);
    };

    return (
        <>
            <Field
                label="Private key"
                rows={2}
                growWithContent
                value={privateKey}
                error={errors.privateKey}
                placeholder="Hex, base64, PEM, OpenSSH or JWK (not a minisign secret key file, which is encrypted)"
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
                value={message}
                onInput={(value) => {
                    setMessage(value);
                    clear('message');
                }}
                format={messageFormat}
                onFormatChange={(format) => {
                    setMessageFormat(format);
                    clear('message');
                }}
                error={errors.message}
                file={file}
                onFile={(chosen) => {
                    setFile(chosen);
                    clear('message');
                }}
                onFileError={(error) => setErrors((current) => ({ ...current, message: error }))}
            />
            <Field
                label="Trusted comment (optional)"
                rows={1}
                value={comment}
                error={errors.comment}
                hint="One line, signed together with the signature: whoever verifies sees it and knows it was not changed. minisign writes the time and the file name here."
                onInput={(value) => {
                    setComment(value);
                    clear('comment');
                }}
            />
            <Field
                label="Key ID (optional)"
                rows={1}
                value={keyId}
                error={errors.keyId}
                placeholder="B74960C202F410C9"
                hint="A plain Ed25519 key has no minisign key ID. Empty: one is made from the key, and the public key file below carries it. To match an existing minisign key, give its ID (it is in its .pub file)."
                onInput={(value) => {
                    setKeyId(value);
                    clear('keyId');
                }}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={sign}>
                    Sign
                </button>
                <ExampleButton onClick={loadNextExample} />
            </div>
            <ExampleNote example={exampleIndex === null ? null : MINISIGN_EXAMPLES[exampleIndex]} />
            {result && (
                <>
                    <Banner kind="success">
                        <div class="result-head">
                            <strong>Signature:</strong>
                            <div class="field-actions">
                                <CopyButton text={result.armored} label="Copy signature" />
                                <DownloadButton filename="signature.minisig" text={result.armored} label="Download signature" />
                            </div>
                        </div>
                        <pre class="armor">{result.armored}</pre>
                        {published === result.armored && <p>Identical to the signature made by minisign.</p>}
                    </Banner>
                    <Field
                        label="Public key to verify it"
                        rows={2}
                        value={result.publicFile}
                        copyable
                        disabled
                        hint={`minisign public key, ID ${result.keyId}`}
                        download={{ filename: 'minisign.pub' }}
                    />
                </>
            )}
        </>
    );
}

/** Both stay mounted, so what was typed in one is still there after a look at the other. */
export default function MinisignPanel({
    mode,
    initial,
    initialFile,
    autoVerify,
}: {
    mode: 'verify' | 'create';
    initial?: Partial<SharedMinisign>;
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
