import '@testing-library/jest-dom/extend-expect'
import { render, fireEvent } from "@testing-library/svelte";
import FormVerify from "../FormVerify.svelte";

test("should render", () => {
    const results = render(FormVerify);
    expect(() => results.getByText('Public key')).not.toThrow();
});

test("should render with error banner", async () => {
    const results = render(FormVerify);
    const veryButton = results.getByText('Verify');
    await fireEvent.click(veryButton);
    await new Promise((resolve): void => {
        setTimeout(resolve);
    });
    let alert = results.getByRole("alert");
    expect(alert.textContent.trim()).toBe("Signature is wrong");
});

test("should render with valid banner", async () => {
    const results = render(FormVerify, {
        message: "000000102",
        signature: "BhqKbhnVH3kaNARj/Vht7ImJJ2LMM5TOla7k5OTITjdZ+GpWTY69wH79vRowPmq0c2KFDNipPsUcXSAwrviqDA==",
        publicKey: "u6xMxXSXi/dL9tWPS+qfxiOHMA6c2Czwh/k2hy/wx/U=",
    });
    const veryButton = results.getByText('Verify');
    await fireEvent.click(veryButton);
    await new Promise((resolve): void => {
        setTimeout(resolve);
    });
    let alert = results.getByRole("alert");
    expect(alert.textContent.trim()).toBe("Signature is valid");
});
