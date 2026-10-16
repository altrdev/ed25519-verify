import Segmented from './Segmented';
import { outputEncoding } from './store';
import { SignEncoding } from './enum';

const OPTIONS = [
    { value: SignEncoding.Hex, label: 'Hex' },
    { value: SignEncoding.Base64, label: 'Base64' },
];

/** Chooses how results are written. Keys and signatures typed or pasted in are recognised by themselves. */
export default function SelectorEncoding() {
    return (
        <div class="encoding">
            <span class="encoding-label" id="encoding-label">Show results as</span>
            <Segmented
                options={OPTIONS}
                value={outputEncoding.value}
                labelledBy="encoding-label"
                onChange={(encoding) => {
                    outputEncoding.value = encoding;
                }}
            />
        </div>
    );
}
