import Segmented from './Segmented';
import { MessageFormat } from './enum';

const OPTIONS = [
    { value: MessageFormat.Text, label: 'Text' },
    { value: MessageFormat.Hex, label: 'Hex' },
    { value: MessageFormat.Base64, label: 'Base64' },
];

export default function MessageFormatSelector({ value, onChange }: { value: MessageFormat; onChange: (format: MessageFormat) => void }) {
    return <Segmented options={OPTIONS} value={value} label="Message format" onChange={onChange} />;
}
