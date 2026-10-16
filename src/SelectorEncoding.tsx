import { encodingDefault } from './store';
import { SignEncoding } from './enum';

export default function SelectorEncoding({ reset = () => {} }: { reset?: () => void }) {
    const select = (encoding: SignEncoding) => {
        reset();
        encodingDefault.value = encoding;
    };

    return (
        <div class="encoding">
            <span class="encoding-label" id="encoding-label">Encoding</span>
            <div class="segmented small" role="group" aria-labelledby="encoding-label">
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
        </div>
    );
}
