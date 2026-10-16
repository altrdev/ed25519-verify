import Segmented from './Segmented';
import { encodingDefault } from './store';
import { SignEncoding } from './enum';

const OPTIONS = [
    { value: SignEncoding.Hex, label: 'Hex' },
    { value: SignEncoding.Base64, label: 'Base64' },
];

export default function SelectorEncoding({ reset = () => {} }: { reset?: () => void }) {
    return (
        <div class="encoding">
            <span class="encoding-label" id="encoding-label">Keys and signature encoding</span>
            <Segmented
                options={OPTIONS}
                value={encodingDefault.value}
                labelledBy="encoding-label"
                onChange={(encoding) => {
                    reset();
                    encodingDefault.value = encoding;
                }}
            />
        </div>
    );
}
