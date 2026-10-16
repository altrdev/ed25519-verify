import { useEffect, useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import { type Hints, diagnose } from './diagnose';
import DownloadButton from './DownloadButton';
import { ExampleButton, ExampleNote, nextIndex } from './ExampleButton';
import { SSHSIG_EXAMPLES, type SshsigExample } from './examples';
import Field from './Field';
import { readingHint } from './FormatMenu';
import HintList from './HintList';
import { encodeOpenSshPublic } from './keyfiles';
import MessageField from './MessageField';
import type { MessageFile } from './messagefile';
import { MessageFormat, type RawFormat } from './enum';
import Segmented from './Segmented';
import { type SharedSshsig, sshsigShareFragment } from './share';
import VerifyEd25519, { type FormatOverrides, inspectField, type Verdict, verdictOf } from './signature';
import {
    checkNamespace,
    fingerprint,
    type HashAlgorithm,
    type ParsedSshsig,
    parseSshsig,
    signedData,
    signedDataOf,
    SshsigError,
    signSshsig,
} from './sshsig';

type Errors = Partial<Record<'signature' | 'publicKey' | 'namespace' | 'message' | 'privateKey', string>>;

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, i) => value === b[i]);
const asError = (error: unknown) => {
    if (error instanceof SshsigError) return error.message;
    throw error;
};

interface Shown {
    verdict: Verdict;
    parsed: ParsedSshsig;
    fingerprint: string;
    /** the verification used the key the user gave; otherwise the key inside the signature */
    trusted: boolean;
    size: number;
    hints?: Hints;
}

const bytesLabel = (size: number) => `${size.toLocaleString('en-US')} byte${size === 1 ? '' : 's'}`;

function Details({ shown }: { shown: Shown }) {
    return (
        <section class="decoded" aria-label="Signature details">
            <h2>What the signature says</h2>
            <ul>
                <li>
                    Namespace: <strong>{shown.parsed.namespace}</strong> (what it was made for)
                </li>
                <li>Hash of the message: {shown.parsed.hashAlgorithm}</li>
                <li>Key inside it: {shown.fingerprint}</li>
                <li>Message: {bytesLabel(shown.size)}</li>
            </ul>
        </section>
    );
}

function Verify({ initial, autoVerify }: { initial?: Partial<SharedSshsig>; autoVerify?: boolean }) {
    const [signature, setSignature] = useState(initial?.signature ?? '');
    const [publicKey, setPublicKey] = useState(initial?.publicKey ?? '');
    const [namespace, setNamespace] = useState(initial?.namespace ?? '');
    const [message, setMessage] = useState(initial?.message ?? '');
    const [messageFormat, setMessageFormat] = useState(initial?.messageFormat ?? MessageFormat.Text);
    const [file, setFile] = useState<MessageFile | null>(null);
    const [errors, setErrors] = useState<Errors>({});
    const [choices, setChoices] = useState<RawFormat[] | undefined>(undefined);
    const [formats, setFormats] = useState<FormatOverrides>({});
    const [shown, setShown] = useState<Shown | null>(null);
    const [exampleIndex, setExampleIndex] = useState<number | null>(null);

    const publicKeyReading = inspectField('publicKey', publicKey, formats.publicKey);

    const verify = async (
        picked: FormatOverrides = formats,
        values = { signature, publicKey, namespace, message, messageFormat, file },
    ) => {
        const found: Errors = {};
        let parsed: ParsedSshsig | undefined;
        try {
            parsed = parseSshsig(values.signature);
        } catch (error) {
            found.signature = asError(error);
        }

        let trusted: Uint8Array | undefined;
        if (values.publicKey.trim()) {
            const key = new VerifyEd25519('', null, values.publicKey, null, undefined, picked);
            found.publicKey = key.validate(['publicKey']).publicKey;
            setChoices(key.choices(['publicKey']).publicKey);
            if (!found.publicKey) trusted = key.bytesOf('publicKey');
        } else {
            setChoices(undefined);
        }

        const given = values.file?.bytes ?? values.message;
        const messageReader = new VerifyEd25519(given, null, null, null, values.messageFormat);
        found.message = messageReader.validate(['message']).message;

        if (parsed && values.namespace.trim() && values.namespace.trim() !== parsed.namespace) {
            found.namespace = `The signature is for the namespace "${parsed.namespace}", not "${values.namespace.trim()}": a signature made for one purpose is not valid for another.`;
        }
        const embedded = parsed ? await fingerprint(parsed.publicKey) : '';
        if (parsed && trusted && !sameBytes(trusted, parsed.publicKey)) {
            found.publicKey = `This signature was made by the key ${embedded}, not by the key you gave (${await fingerprint(trusted)}).`;
        }

        setErrors(found);
        if (!parsed || found.publicKey || found.message || found.namespace) {
            setShown(null);
            return;
        }
        const bytes = messageReader.messageBytes();
        const key = trusted ?? parsed.publicKey;
        const verdict = await verdictOf(parsed.signature, await signedDataOf(parsed, bytes), key);
        setShown({
            verdict,
            parsed,
            fingerprint: embedded,
            trusted: !!trusted,
            size: bytes.length,
            // the usual mistakes about the message (a newline, a format), tried through the structure that is signed
            hints:
                verdict === 'invalid'
                    ? await diagnose(
                          {
                              publicKey: key,
                              signature: parsed.signature,
                              message: given,
                              messageFormat: values.messageFormat,
                              skipHashes: true,
                              frame: (candidate) => signedData(candidate, parsed),
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

    const loadExample = (example: SshsigExample) => {
        const values = {
            signature: example.signature,
            publicKey: example.publicKey,
            namespace: '',
            message: example.message,
            messageFormat: MessageFormat.Text,
            file: null,
        };
        setSignature(values.signature);
        setPublicKey(values.publicKey);
        setNamespace('');
        setMessage(values.message);
        setMessageFormat(MessageFormat.Text);
        setFile(null);
        setErrors({});
        setChoices(undefined);
        setFormats({});
        verify({}, values);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, SSHSIG_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(SSHSIG_EXAMPLES[index]);
    };

    const fragment = sshsigShareFragment({ signature, publicKey, namespace, message: file ? '' : message, messageFormat });
    const shareable = fragment !== '' && !file;
    const link = () => `${location.origin}${location.pathname}${location.search}${fragment}`;

    return (
        <>
            <Field
                label="Signature"
                rows={5}
                value={signature}
                error={errors.signature}
                placeholder="-----BEGIN SSH SIGNATURE----- … (the file made by ssh-keygen -Y sign)"
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
                hint={readingHint(publicKeyReading)}
                placeholder="ssh-ed25519 AAAA… (an authorized_keys line, or any format of a public key)"
                fileKind="key"
                onInput={(value) => {
                    setPublicKey(value);
                    reset('publicKey');
                    setChoices(undefined);
                    setFormats((current) => ({ ...current, publicKey: undefined }));
                }}
            />
            <Field
                label="Namespace (optional)"
                rows={1}
                value={namespace}
                error={errors.namespace}
                hint='What you expect the signature to be for ("file", "git", "email"...). Empty: the one in the signature is taken and shown.'
                onInput={(value) => {
                    setNamespace(value);
                    reset('namespace');
                }}
            />
            <div class="actions">
                <button type="button" class="primary" onClick={() => verify()}>
                    Verify
                </button>
                <CopyButton text={shareable ? link() : ''} label="Copy link to this verification" caption="Copy link" />
                <ExampleButton onClick={loadNextExample} />
            </div>
            <ExampleNote example={exampleIndex === null ? null : SSHSIG_EXAMPLES[exampleIndex]} />
            {shown?.verdict === 'valid' && shown.trusted && <Banner kind="success">Signature is valid</Banner>}
            {shown?.verdict === 'valid' && !shown.trusted && (
                <Banner kind="warning">
                    The signature is valid for the key inside it, {shown.fingerprint}. Nothing says that it is the key you trust: paste that
                    key above to check it.
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
    const [namespace, setNamespace] = useState('file');
    const [hash, setHash] = useState<HashAlgorithm>('sha512');
    const [message, setMessage] = useState('');
    const [messageFormat, setMessageFormat] = useState(MessageFormat.Text);
    const [file, setFile] = useState<MessageFile | null>(null);
    const [errors, setErrors] = useState<Errors>({});
    const [result, setResult] = useState<{ armored: string; publicKey: string; fingerprint: string } | null>(null);

    const sign = async () => {
        const found: Errors = {};
        try {
            checkNamespace(namespace);
        } catch (error) {
            found.namespace = asError(error);
        }
        const signer = new VerifyEd25519(file?.bytes ?? message, null, null, privateKey, messageFormat);
        const fields = signer.validate(['privateKey', 'message']);
        found.privateKey = fields.privateKey;
        found.message = fields.message;
        setErrors(found);
        if (found.namespace || found.privateKey || found.message) {
            setResult(null);
            return;
        }
        const seed = (await signer.bytesOf('privateKey')).slice(0, 32);
        const { armored, publicKey } = await signSshsig(signer.messageBytes(), seed, { namespace, hashAlgorithm: hash });
        setResult({ armored, publicKey: encodeOpenSshPublic(publicKey), fingerprint: await fingerprint(publicKey) });
    };

    const clear = (field: keyof Errors) => {
        setResult(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
    };

    const loadExample = (example: SshsigExample) => {
        setPrivateKey(example.privateKey);
        setNamespace(example.namespace);
        setHash(example.hashAlgorithm);
        setMessage(example.message);
        setMessageFormat(MessageFormat.Text);
        setFile(null);
        setRevealed(true);
        setErrors({});
        setResult(null);
        setPublished(example.signature);
    };

    const loadNextExample = () => {
        const index = nextIndex(exampleIndex, SSHSIG_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(SSHSIG_EXAMPLES[index]);
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
                label="Namespace"
                rows={1}
                value={namespace}
                error={errors.namespace}
                hint='What the signature is for: "file" (ssh-keygen default), "git", "email"... Whoever verifies must give the same one.'
                onInput={(value) => {
                    setNamespace(value);
                    clear('namespace');
                }}
            />
            <div class="mode-row">
                <Segmented
                    label="Hash"
                    value={hash}
                    onChange={(value) => {
                        setHash(value);
                        setResult(null);
                    }}
                    options={[
                        { value: 'sha512', label: 'SHA-512' },
                        { value: 'sha256', label: 'SHA-256' },
                    ]}
                />
            </div>
            <div class="actions">
                <button type="button" class="primary" onClick={sign}>
                    Sign
                </button>
                <ExampleButton onClick={loadNextExample} />
            </div>
            <ExampleNote example={exampleIndex === null ? null : SSHSIG_EXAMPLES[exampleIndex]} />
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
                        {published === result.armored && <p>Identical to the signature made by ssh-keygen.</p>}
                    </Banner>
                    <Field
                        label="Public key to verify it"
                        rows={2}
                        value={result.publicKey}
                        copyable
                        disabled
                        hint={result.fingerprint}
                        download={{ filename: 'id_ed25519.pub' }}
                    />
                </>
            )}
        </>
    );
}

/** Both stay mounted, so what was typed in one is still there after a look at the other. */
export default function SshsigPanel({
    mode,
    initial,
    autoVerify,
}: {
    mode: 'verify' | 'create';
    initial?: Partial<SharedSshsig>;
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
