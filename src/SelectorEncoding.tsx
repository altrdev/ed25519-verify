import { encodingDefault } from './store';
import { SignEncoding } from './enum';

export default function SelectorEncoding({ reset = () => {} }: { reset?: () => void }) {
    const select = (encoding: SignEncoding) => {
        reset();
        encodingDefault.value = encoding;
    };

    return (
        <div class="segmented" role="group" aria-label="Encoding">
            {[SignEncoding.Hex, SignEncoding.Base64].map((encoding) => (
                <button
                    type="button"
                    key={encoding}
                    class={encodingDefault.value === encoding ? 'active' : ''}
                    aria-pressed={encodingDefault.value === encoding}
                    onClick={() => select(encoding)}
                >
                    {encoding === SignEncoding.Hex ? 'Hex' : 'Base64'}
                </button>
            ))}
        </div>
    );
}
