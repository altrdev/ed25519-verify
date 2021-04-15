import '@testing-library/jest-dom/extend-expect'
import { render, fireEvent } from "@testing-library/svelte";
import FormSign from "../FormSign.svelte";

describe('FormSign component', function() {
    it("should render", () => {
        const results = render(FormSign);
        expect(() => results.getByText('Private key')).not.toThrow();
    });

    it("should render with error banner", async () => {
        const results = render(FormSign);
        const signButton = results.getByText('Sign');
        await fireEvent.click(signButton);
        await new Promise((resolve): void => {
            setTimeout(resolve);
        });
        let alert = results.getByRole("alert");
        expect(alert.textContent.trim()).toBe("Signature can't be performed. Private key is mandatory");
    });

    it("should render with valid banner", async () => {
        const results = render(FormSign, {
            message: "000000102",
            privateKey: "mockprivatekey",
            signature: ""
        });
        const signButton = results.getByText('Sign');
        await fireEvent.click(signButton);
        await new Promise((resolve): void => {
            setTimeout(resolve);
        });
        let alert = results.getByRole("alert");
        expect(alert.textContent.trim()).toContain("Signature:");
    });
})
