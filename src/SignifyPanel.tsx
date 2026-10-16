import { useEffect, useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import { type Hints, diagnose } from './diagnose';
import DownloadButton from './DownloadButton';
import { ExampleButton, ExampleNote, nextIndex } from './ExampleButton';
import { MessageFormat, type RawFormat } from './enum';
import { SIGNIFY_EXAMPLES, type SignifyExample } from './examples';
import Field from './Field';
import { readingHint } from './FormatMenu';
import HintList from './HintList';
import {
    keyNumberText,
    looksLikeSignifyPublic,
    SignifyError,
    type SignifyPublic,
    type ParsedSignify,
    parseKeyNumber,
    parseSignify,
    parseSignifyPublic,
    signSignify,
} from './signify';
import MessageField from './MessageField';
import type { MessageFile } from './messagefile';
import { signifyShareFragment, type SharedSignify } from './share';
import VerifyEd25519, { type FormatOverrides, inspectField, type Verdict, verdictOf } from './signature';

type Errors = Partial<Record<'signature' | 'publicKey' | 'message' | 'privateKey' | 'keyNumber', string>>;

const asError = (error: unknown) => {
    if (error instanceof SignifyError) return error.message;
    throw error;
};

interface Shown {
    verdict: Verdict;
    parsed: ParsedSignify;
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
                    Key number: <strong>{keyNumberText(parsed.keyNumber)}</strong> (hex, as in the file)
                </li>
                <li>Message: {bytesLabel(shown.size)}</li>
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
    initial?: Partial<SharedSignify>;
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

    const isSignifyKey = looksLikeSignifyPublic(publicKey);
    const publicKeyReading = isSignifyKey ? null : inspectField('publicKey', publicKey, formats.publicKey);
    const signifyKey = (() => {
        try {
            return isSignifyKey ? parseSignifyPublic(publicKey) : null;
        } catch {
            return null;
        }
    })();

    const verify = async (picked: FormatOverrides = formats, values = { signature, publicKey, message, messageFormat, file }) => {
        const found: Errors = {};
        let parsed: ParsedSignify | undefined;
        try {
            parsed = parseSignify(values.signature);
        } catch (error) {
            found.signature = asError(error);
        }

        let key: Uint8Array | undefined;
        let identified: SignifyPublic | undefined;
        if (!values.publicKey.trim()) {
            found.publicKey = 'The public key is needed: a signify signature does not carry it, only the number of the key that made it.';
            setChoices(undefined);
        } else if (looksLikeSignifyPublic(values.publicKey)) {
            identified = parseSignifyPublic(values.publicKey);
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

        if (parsed && identified && keyNumberText(parsed.keyNumber) !== keyNumberText(identified.keyNumber)) {
            found.publicKey = `This signature was made by the key number ${keyNumberText(parsed.keyNumber)}, not by the key you gave (${keyNumberText(identified.keyNumber)}).`;
        }

        setErrors(found);
        if (!parsed || !key || found.publicKey || found.message) {
            setShown(null);
            return;
        }
        const bytes = messageReader.messageBytes();
        const verdict = await verdictOf(parsed.signature, bytes, key);
        setShown({
            verdict,
            parsed,
            size: bytes.length,
            hints:
                verdict === 'invalid'
                    ? await diagnose(
                          { publicKey: key, signature: parsed.signature, message: given, messageFormat: values.messageFormat },
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

    const loadExample = (example: SignifyExample) => {
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
        const index = nextIndex(exampleIndex, SIGNIFY_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(SIGNIFY_EXAMPLES[index]);
    };

    const fragment = signifyShareFragment({ signature, publicKey, message: file ? '' : message, messageFormat });
    const shareable = fragment !== '' && !file;
    const link = () => `${location.origin}${location.pathname}${location.search}${fragment}`;

    return (
        <>
            <Field
                label="Signature"
                rows={4}
                value={signature}
                error={errors.signature}
                placeholder="untrusted comment: … (the content of the .sig file)"
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
                hint={signifyKey ? `signify public key, key number ${keyNumberText(signifyKey.keyNumber)}` : readingHint(publicKeyReading)}
                placeholder="RWQ… (the signify .pub file, or its second line), or a public key in any other format"
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
            <ExampleNote example={exampleIndex === null ? null : SIGNIFY_EXAMPLES[exampleIndex]} />
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
    const [keyNumber, setKeyId] = useState('');
    const [message, setMessage] = useState('');
    const [messageFormat, setMessageFormat] = useState(MessageFormat.Text);
    const [file, setFile] = useState<MessageFile | null>(null);
    const [errors, setErrors] = useState<Errors>({});
    const [result, setResult] = useState<{ armored: string; publicFile: string; keyNumber: string } | null>(null);

    const sign = async () => {
        const found: Errors = {};
        let id: Uint8Array | undefined;
        try {
            if (keyNumber.trim()) id = parseKeyNumber(keyNumber);
        } catch (error) {
            found.keyNumber = asError(error);
        }
        const signer = new VerifyEd25519(file?.bytes ?? message, null, null, privateKey, messageFormat);
        const fields = signer.validate(['privateKey', 'message']);
        found.privateKey = fields.privateKey;
        found.message = fields.message;
        setErrors(found);
        if (found.keyNumber || found.privateKey || found.message) {
            setResult(null);
            return;
        }
        const seed = (await signer.bytesOf('privateKey')).slice(0, 32);
        const made = await signSignify(signer.messageBytes(), seed, { keyNumber: id });
        setResult({ armored: made.armored, publicFile: made.publicFile, keyNumber: keyNumberText(made.keyNumber) });
    };

    const clear = (field: keyof Errors) => {
        setResult(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
    };

    const loadExample = (example: SignifyExample) => {
        setPrivateKey(example.privateKey);
        setKeyId(example.keyNumber);
        setMessage(example.message);
        setMessageFormat(MessageFormat.Text);
        setFile(null);
        setRevealed(true);
        setErrors({});
        setResult(null);
        setPublished(example.signature);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, SIGNIFY_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(SIGNIFY_EXAMPLES[index]);
    };

    return (
        <>
            <Field
                label="Private key"
                rows={2}
                growWithContent
                value={privateKey}
                error={errors.privateKey}
                placeholder="Hex, base64, PEM, OpenSSH or JWK (not a signify secret key file, which is usually encrypted)"
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
                label="Key number (optional)"
                rows={1}
                value={keyNumber}
                error={errors.keyNumber}
                placeholder="137a6ab64cfb746b"
                hint="A plain Ed25519 key has no signify key number. Empty: one is made from the key, and the public key file below carries it. To match an existing signify key, give its number: 16 hexadecimal digits, the 8 bytes after the Ed in its .pub file (signify does not print it)."
                onInput={(value) => {
                    setKeyId(value);
                    clear('keyNumber');
                }}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={sign}>
                    Sign
                </button>
                <ExampleButton onClick={loadNextExample} />
            </div>
            <ExampleNote example={exampleIndex === null ? null : SIGNIFY_EXAMPLES[exampleIndex]} />
            {result && (
                <>
                    <Banner kind="success">
                        <div class="result-head">
                            <strong>Signature:</strong>
                            <div class="field-actions">
                                <CopyButton text={result.armored} label="Copy signature" />
                                <DownloadButton filename="signature.sig" text={result.armored} label="Download signature" />
                            </div>
                        </div>
                        <pre class="armor">{result.armored}</pre>
                        {published === result.armored && <p>Identical to the signature made by signify.</p>}
                    </Banner>
                    <Field
                        label="Public key to verify it"
                        rows={2}
                        value={result.publicFile}
                        copyable
                        disabled
                        hint={`signify public key, key number ${result.keyNumber}`}
                        download={{ filename: 'signify.pub' }}
                    />
                </>
            )}
        </>
    );
}

/** Both stay mounted, so what was typed in one is still there after a look at the other. */
export default function SignifyPanel({
    mode,
    initial,
    initialFile,
    autoVerify,
}: {
    mode: 'verify' | 'create';
    initial?: Partial<SharedSignify>;
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
