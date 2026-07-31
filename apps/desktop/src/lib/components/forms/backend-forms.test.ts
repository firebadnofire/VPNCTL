import { render, screen } from "@testing-library/svelte";
import { describe, expect, it } from "vitest";
import BackendFormHarness from "../../../test/BackendFormHarness.svelte";

describe("backend form isolation", () => {
  it("renders real fields for all five backends", () => {
    const wireguard = render(BackendFormHarness, { kind: "wireguard" });
    expect(screen.getByRole("checkbox", { name: /userspace fallback/i })).toBeTruthy();
    wireguard.unmount();

    const awg = render(BackendFormHarness, { kind: "amnezia_wg" });
    const advanced = screen.getByText("AWG2 obfuscation settings").closest("details");
    expect(advanced?.open).toBe(false);
    expect((screen.getByLabelText("Jc") as HTMLInputElement).value).toBe("5");
    awg.unmount();

    const openvpn = render(BackendFormHarness, { kind: "openvpn" });
    expect(screen.getByLabelText("Data cipher")).toBeTruthy();
    openvpn.unmount();

    const ikev2 = render(BackendFormHarness, { kind: "ikev2" });
    expect(screen.getByText(/UDP 500 and 4500/)).toBeTruthy();
    expect(screen.getByText(/password-protected PKCS#12/)).toBeTruthy();
    ikev2.unmount();

    const xray = render(BackendFormHarness, { kind: "xray" });
    expect(screen.getByLabelText("SNI / camouflage host")).toBeTruthy();
    expect(screen.queryByText("Certificate file")).toBeNull();
    expect(document.body.textContent).not.toContain("PRIVATE KEY");
    xray.unmount();
  });
});
