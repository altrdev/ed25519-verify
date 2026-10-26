import { render, screen } from '@testing-library/preact';
import Checks, { checksOf } from '../Checks';
import { hexToBytes } from '../bytes';
import { EXAMPLES } from '../examples';

const example = EXAMPLES[0];
const publicKey = hexToBytes(example.publicKey);
const signature = hexToBytes(example.signature);
const states = (checks: ReturnType<typeof checksOf>) => checks.map((check) => check.state);

describe('the checks of a verification', () => {
    it('passes every step for a valid signature', () => {
        expect(states(checksOf(signature, publicKey, 'valid'))).toEqual(['ok', 'ok', 'ok', 'ok', 'ok', 'ok']);
    });

    it('fails only the equation for a signature that is well formed and wrong', () => {
        expect(states(checksOf(signature, publicKey, 'invalid'))).toEqual(['ok', 'ok', 'ok', 'ok', 'ok', 'fail']);
    });

    it('fails the step of an S that is not reduced, and does not reach the equation', () => {
        const unreduced = signature.slice();
        unreduced.fill(0xff, 32);
        expect(states(checksOf(unreduced, publicKey, 'invalid'))).toEqual(['ok', 'ok', 'ok', 'ok', 'fail', 'skip']);
    });

    it('says the equation holds only under the permissive rules', () => {
        const equation = checksOf(signature, publicKey, 'permissive-only').at(-1);
        expect(equation).toMatchObject({ state: 'fail', detail: 'only under ZIP215' });
    });

    it('fails a key that is not a point of the curve', () => {
        const notAPoint = new Uint8Array(32).fill(0xff);
        expect(checksOf(signature, notAPoint, 'invalid')[2].state).toBe('fail');
    });

    it('lists the steps with their outcome for a screen reader', () => {
        render(<Checks signature={signature} publicKey={publicKey} verdict="invalid" />);
        expect(screen.getByRole('list', { name: 'What was checked' })).toBeInTheDocument();
        expect(screen.getByText('The equation [S]B = R + [k]A holds').closest('li')).toHaveTextContent('failed');
    });
});
