import { useEffect, useState } from 'preact/hooks';
import Banner from './Banner';
import CopyButton from './CopyButton';
import { type Hints, diagnose } from './diagnose';
import { ExampleButton, ExampleNote, nextIndex } from './ExampleButton';
import { MessageFormat, type RawFormat } from './enum';
import { type PgpExample, PGP_EXAMPLES } from './examples';
import Field from './Field';
import { readingHint } from './FormatMenu';
import HintList from './HintList';
import MessageField from './MessageField';
import type { MessageFile } from './messagefile';
import {
    candidateKeys,
    type CertificateReview,
    HASH_NAMES,
    PgpError,
    type PgpCertificate,
    type PgpKey,
    type ParsedPgpSignature,
    parseCertificate,
    parsePgpSignature,
    readPgp,
    REVOCATION_REASONS,
    type Revocation,
    reviewCertificate,
    SIGNATURE_TYPES,
    signedHash,
    spaced,
    type Standing,
    standingOf,
    type UserIdReview,
} from './openpgp';
import { pgpShareFragment, type SharedPgp } from './share';
import VerifyEd25519, { type FormatOverrides, inspectField, type Verdict, verdictOf } from './signature';
import Results from './Results';
import Checks from './Checks';
import { VerdictPill, VerdictScope, VerifyButton } from './Verdict';

type Errors = Partial<Record<'signature' | 'publicKey' | 'message', string>>;

const asError = (error: unknown) => {
    if (error instanceof PgpError) return error.message;
    throw error;
};

interface Shown {
    verdict: Verdict;
    publicKey: Uint8Array;
    parsed: ParsedPgpSignature;
    /** the key that made it (one of the block), or null when a plain key was given */
    key: PgpKey | null;
    /** what the key block says about the keys and user IDs (its own signatures, expiry, revocations), null for a plain key */
    review: CertificateReview | null;
    standing: Standing | null;
    /** the hash of the message starts with the two bytes the signature keeps */
    prefixMatches: boolean;
    size: number;
    cleartext: boolean;
    hints?: Hints;
}

const bytesLabel = (size: number) => `${size.toLocaleString('en-US')} byte${size === 1 ? '' : 's'}`;
const when = (seconds: number) => `${new Date(seconds * 1000).toISOString().replace('.000Z', 'Z').replace('T', ' ')}`;
const looksLikeBlock = (text: string) => /-----BEGIN PGP (PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----/.test(text);
const day = (seconds: number) => new Date(seconds * 1000).toISOString().slice(0, 10);

const revocationText = (revocation: Revocation) =>
    `revoked${revocation.created !== undefined ? ` on ${day(revocation.created)}` : ''} (${REVOCATION_REASONS[revocation.code] ?? `reason ${revocation.code}`}${revocation.text ? `: "${revocation.text}"` : ''})`;

/** A user ID as the block shows it, and what was found about it: only a signature of the key over it that verifies makes it more than a claim. */
function userIdText(user: UserIdReview) {
    const revoked = user.revocations.find((revocation) => revocation.check === 'checked');
    const certification = {
        checked: 'signed by the key itself (checked)',
        missing: 'no signature of the key over it in this block: the block only claims it',
        wrong: 'its signature by the key does not verify: the block was altered',
        unchecked: `could not be checked${user.note ? ` (${user.note.replace(/\.$/, '')})` : ''}`,
    }[user.certification];
    return `${user.userId}: ${certification}${revoked ? `; ${revocationText(revoked)}` : ''}`;
}

function Details({ shown }: { shown: Shown }) {
    const { parsed, key } = shown;
    const expires = parsed.created !== undefined && parsed.expires ? parsed.created + parsed.expires : undefined;
    return (
        <section class="decoded" aria-label="Signature details">
            <h2>What the signature says</h2>
            <ul>
                <li>
                    Signature of {SIGNATURE_TYPES[parsed.type]}, version {parsed.version},{' '}
                    {parsed.algorithm === 27 ? 'Ed25519 (algorithm 27)' : 'EdDSA (algorithm 22)'}, hash {HASH_NAMES[parsed.hash]}
                </li>
                {parsed.created !== undefined && <li>Made on {when(parsed.created)} UTC (the time the signer wrote in it)</li>}
                {expires !== undefined && (
                    <li>
                        The signature {expires * 1000 < Date.now() ? 'expired' : 'expires'} on {when(expires)} UTC
                    </li>
                )}
                {key ? (
                    <li>
                        Key: {spaced(key.fingerprint)} ({key.primary ? 'the primary key' : 'a subkey'}, version {key.version})
                    </li>
                ) : (
                    parsed.issuerFingerprint && (
                        <li>It names the key {spaced(parsed.issuerFingerprint)}, which was not compared with the key you gave.</li>
                    )
                )}
                {shown.review?.userIds.map((user) => (
                    <li key={user.userId}>User ID {userIdText(user)}</li>
                ))}
                {shown.review && shown.review.othersCertifications > 0 && (
                    <li>
                        {shown.review.othersCertifications} certification{shown.review.othersCertifications === 1 ? '' : 's'} of its user
                        IDs by other keys: that is the web of trust, which this page does not look at.
                    </li>
                )}
                {shown.verdict !== 'valid' && // for a valid signature the verdict banner already says them
                    shown.standing?.issues.map((issue) => <li key={issue}>{issue}</li>)}
                {shown.standing?.facts.map((fact) => (
                    <li key={fact}>{fact}</li>
                ))}
                <li>
                    Message: {shown.cleartext ? 'the text of the cleartext message, ' : ''}
                    {bytesLabel(shown.size)}
                </li>
                <li>
                    {shown.prefixMatches
                        ? 'The hash of the message starts with the 2 bytes that the signature keeps: it is the message that was signed.'
                        : 'The hash of the message does not start with the 2 bytes that the signature keeps: it is not the message that was signed.'}
                </li>
            </ul>
            <p class="muted">
                {shown.review
                    ? 'This looks only inside the key block you pasted: the signature, the signatures that bind its user IDs and subkeys to the primary key, its expiry dates and the revocations it holds. It does not know whether anyone certified the key (the web of trust), and a revocation or a new expiry date published elsewhere, on a keyserver for instance, is not in this block: "no revocation here" is not "not revoked". Check the fingerprint with the owner of the key.'
                    : 'A plain key carries nothing to look at: whether it is certified, expired or revoked was not checked, only the mathematics. Check the fingerprint with the owner of the key.'}
            </p>
        </section>
    );
}

function Verify({
    initial,
    initialFile,
    autoVerify,
}: {
    initial?: Partial<SharedPgp>;
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

    const isBlock = looksLikeBlock(publicKey);
    const publicKeyReading = isBlock ? null : inspectField('publicKey', publicKey, formats.publicKey);

    const verify = async (picked: FormatOverrides = formats, values = { signature, publicKey, message, messageFormat, file }) => {
        const found: Errors = {};
        let parsed: ParsedPgpSignature | undefined;
        let cleartextBytes: Uint8Array | undefined;
        try {
            const read = readPgp(values.signature);
            if ('cleartext' in read) {
                cleartextBytes = new TextEncoder().encode(read.cleartext.text);
                parsed = parsePgpSignature(read.cleartext.signature);
            } else {
                if (read.armored.kind === 'public key')
                    throw new PgpError('This is a public key, not a signature: paste the key in the field of the public key.');
                parsed = parsePgpSignature(read.armored.bytes);
            }
        } catch (error) {
            found.signature = asError(error);
        }

        // the keys: a block (primary key and subkeys), or a plain Ed25519 key in any format
        let certificate: PgpCertificate | undefined;
        let review: CertificateReview | null = null;
        let plainKey: Uint8Array | undefined;
        if (!values.publicKey.trim()) {
            found.publicKey = 'The public key is needed: a signature names the key that made it but does not carry it.';
            setChoices(undefined);
        } else if (looksLikeBlock(values.publicKey)) {
            setChoices(undefined);
            try {
                const read = readPgp(values.publicKey);
                if (!('armored' in read) || read.armored.kind !== 'public key') throw new PgpError('This is not a public key block.');
                certificate = await parseCertificate(read.armored.bytes);
                review = await reviewCertificate(read.armored.bytes);
            } catch (error) {
                found.publicKey = asError(error);
            }
        } else {
            const reader = new VerifyEd25519('', null, values.publicKey, null, undefined, picked);
            found.publicKey = reader.validate(['publicKey']).publicKey;
            setChoices(reader.choices(['publicKey']).publicKey);
            if (!found.publicKey) plainKey = reader.bytesOf('publicKey');
        }

        // the message: the text of a cleartext message, or the document
        const given = values.file?.bytes ?? values.message;
        const reader = new VerifyEd25519(given, null, null, null, values.messageFormat);
        let document = cleartextBytes;
        if (!cleartextBytes) {
            if (!values.file && !values.message) found.message = 'The message the signature is for is needed.';
            else found.message = reader.validate(['message']).message;
            if (!found.message) document = reader.messageBytes();
        }

        let candidates: PgpKey[] = [];
        if (parsed && certificate) {
            candidates = candidateKeys(parsed, certificate.keys);
            if (candidates.length === 0) {
                const named = parsed.issuerFingerprint ?? parsed.issuerKeyId;
                found.publicKey = named
                    ? `This signature was made by the key ${spaced(named)}, which is not in the key block you gave (${certificate.keys.map((key) => spaced(key.fingerprint)).join(', ')}).`
                    : 'The key block has no key of the algorithm of this signature.';
            }
        }

        let hash: Uint8Array | undefined;
        if (parsed && document) {
            try {
                hash = await signedHash(parsed, document);
            } catch (error) {
                found.signature = asError(error);
            }
        }

        setErrors(found);
        if (!parsed || !document || !hash || found.publicKey || found.message || found.signature) {
            setShown(null);
            return;
        }
        const keys = plainKey
            ? [{ publicKey: plainKey, key: null as PgpKey | null }]
            : candidates.map((key) => ({ publicKey: key.publicKey, key: key as PgpKey | null }));
        let verdict: Verdict = 'invalid';
        let used = keys[0];
        for (const candidate of keys) {
            const result = await verdictOf(parsed.signature, hash, candidate.publicKey);
            if (result === 'valid' || (result === 'permissive-only' && verdict === 'invalid')) {
                verdict = result;
                used = candidate;
                if (result === 'valid') break;
            }
        }
        const parsedSignature = parsed;
        setShown({
            verdict,
            publicKey: used.publicKey,
            parsed,
            key: used.key,
            review,
            standing: review && used.key ? standingOf(review, used.key, parsed) : null,
            prefixMatches: parsed.hashPrefix[0] === hash[0] && parsed.hashPrefix[1] === hash[1],
            size: document.length,
            cleartext: !!cleartextBytes,
            // the usual mistakes about the message, tried through what is really signed (its hash with the header of the signature)
            hints:
                verdict === 'invalid' && !cleartextBytes
                    ? await diagnose(
                          {
                              publicKey: used.publicKey,
                              signature: parsed.signature,
                              message: given,
                              messageFormat: values.messageFormat,
                              skipHashes: true,
                              frame: (candidate) => signedHash(parsedSignature, candidate),
                          },
                          document,
                      )
                    : undefined,
        });
    };

    // a share link: the answer is the first thing the reader sees
    useEffect(() => {
        if (autoVerify && signature && publicKey) verify();
    }, []);

    const reset = (field: keyof Errors) => {
        setShown(null);
        setErrors((current) => ({ ...current, [field]: undefined }));
    };

    const loadExample = (example: PgpExample) => {
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
        const index = nextIndex(exampleIndex, PGP_EXAMPLES.length);
        setExampleIndex(index);
        loadExample(PGP_EXAMPLES[index]);
    };

    const fragment = pgpShareFragment({ signature, publicKey, message: file ? '' : message, messageFormat });
    const shareable = fragment !== '' && !file;
    const link = () => `${location.origin}${location.pathname}${location.search}${fragment}`;

    return (
        <VerdictScope>
            <Field
                label="Signature"
                rows={5}
                value={signature}
                error={errors.signature}
                placeholder="-----BEGIN PGP SIGNATURE----- … (or a whole -----BEGIN PGP SIGNED MESSAGE----- text)"
                fileKind="binary"
                onInput={(value) => {
                    setSignature(value);
                    reset('signature');
                }}
            />
            <MessageField
                hint="Not needed for a cleartext signed message: its text is in the signature."
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
                rows={4}
                value={publicKey}
                error={errors.publicKey}
                choices={choices}
                onChoose={(format) => {
                    const picked = { ...formats, publicKey: format };
                    setFormats(picked);
                    verify(picked);
                }}
                hint={isBlock ? 'OpenPGP public key block' : readingHint(publicKeyReading)}
                placeholder="-----BEGIN PGP PUBLIC KEY BLOCK----- … (gpg --armor --export), or a plain Ed25519 key"
                fileKind="text"
                onInput={(value) => {
                    setPublicKey(value);
                    reset('publicKey');
                    setChoices(undefined);
                    setFormats((current) => ({ ...current, publicKey: undefined }));
                }}
            />
            <div class="actions">
                <VerifyButton onClick={() => verify()} />
                <VerdictPill />
                <CopyButton text={shareable ? link() : ''} label="Copy link to this verification" caption="Copy link" />
                <ExampleButton onClick={loadNextExample} />
            </div>
            <Results>
                <ExampleNote example={exampleIndex === null ? null : PGP_EXAMPLES[exampleIndex]} />
                {shown?.verdict === 'valid' && (
                    <Banner
                        kind={shown.standing?.issues.length ? 'warning' : 'success'}
                        stamp
                        pill={shown.standing?.issues.length ? 'Valid, with notes' : 'Valid'}
                    >
                        <div>Signature is valid</div>
                        {shown.standing && shown.standing.issues.length > 0 && (
                            <>
                                <p>But read it with this, from the key block:</p>
                                <ul>
                                    {shown.standing.issues.map((issue) => (
                                        <li key={issue}>{issue}</li>
                                    ))}
                                </ul>
                            </>
                        )}
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
                {shown && <Details shown={shown} />}
            </Results>
        </VerdictScope>
    );
}

/** OpenPGP is verified only: a key is more than a number there (certified, expired, revoked), and gpg looks after that. */
function Create() {
    return (
        <p class="example-note">
            <strong>Creating OpenPGP signatures is not offered here.</strong> An OpenPGP key carries a certification, an expiry and a
            revocation that a page like this one cannot look after, and a signature should be made where the key lives. Use{' '}
            <code>gpg --armor --detach-sign file</code> (or <code>gpg --clearsign file</code>), then come back to check it with the public
            key.
        </p>
    );
}

export default function PgpPanel({
    mode,
    initial,
    initialFile,
    autoVerify,
}: {
    mode: 'verify' | 'create';
    initial?: Partial<SharedPgp>;
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
