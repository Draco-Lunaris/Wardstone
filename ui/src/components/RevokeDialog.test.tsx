// The RevokeDialog's render states (the render-test pin Task 15 commits
// to): the nine typed reasons are all there with `unspecified` selected;
// a failed revoke surfaces ws-api's message VERBATIM; the submitting
// state disables the buttons; a successful revoke hands the response to
// the caller and closes; a failed revoke does NOT close; the wire body
// is exactly the typed snake_case reason with a trimmed detail.

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import RevokeDialog from "./RevokeDialog";
import type { Certificate, RevokeResponse } from "../lib/certs";

const CERTIFICATE: Certificate = {
  id: "11111111-1111-4111-8111-111111111111",
  tenant_id: "t",
  ca_id: "c",
  profile_revision_id: null,
  profile_name: "Web Server",
  subject: "CN=vpn.example.com",
  serial_hex: "2a",
  san_dns: ["vpn.example.com"],
  san_ips: [],
  key_type: "ecdsa_p256",
  not_before: "2026-10-22T00:00:00Z",
  not_after: "2027-10-22T00:00:00Z",
  cert_pem: "-----BEGIN CERTIFICATE-----",
  status: "active",
  revoked_at: null,
  revocation_reason: null,
  revocation_detail: null,
  source: "manual",
  created_at: "2026-10-22T00:00:00Z",
};

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const REVOKE_201 = (
  id: string,
): RevokeResponse => ({ id, status: "revoked", detail: "stolen" });

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("RevokeDialog", () => {
  it("offers all nine typed reasons with unspecified selected by default", () => {
    render(<RevokeDialog certificate={CERTIFICATE} onClose={() => {}} />);

    const select = screen.getByLabelText(/reason/i) as HTMLSelectElement;
    const values = [...select.options].map((option) => option.value);
    expect(values).toEqual([
      "unspecified",
      "key_compromise",
      "ca_compromise",
      "affiliation_changed",
      "superseded",
      "cessation_of_operation",
      "certificate_hold",
      "privilege_withdrawn",
      "aa_compromise",
    ]);
    expect(select.value).toBe("unspecified");
  });

  it("sends the typed snake_case reason with the trimmed detail and closes on success", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, REVOKE_201(CERTIFICATE.id)));
    vi.stubGlobal("fetch", fetchMock);
    const onClose = vi.fn();
    const onRevoked = vi.fn();

    render(<RevokeDialog certificate={CERTIFICATE} onClose={onClose} onRevoked={onRevoked} />);
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "key_compromise" },
    });
    fireEvent.change(screen.getByLabelText(/detail \(optional\)/i), {
      target: { value: "  the laptop holding this key was stolen  " },
    });
    fireEvent.click(screen.getByRole("button", { name: /^revoke certificate$/i }));

    await vi.waitFor(() => {
      expect(onRevoked).toHaveBeenCalledWith(REVOKE_201(CERTIFICATE.id));
    });
    expect(onClose).toHaveBeenCalledTimes(1);
    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe(`/api/v1/certificates/${CERTIFICATE.id}/revoke`);
    expect(JSON.parse(String(init.body))).toEqual({
      reason: "key_compromise",
      detail: "the laptop holding this key was stolen",
    });
  });

  it("leaves the dialog open and surfaces a failure message verbatim", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(400, {
          error: {
            code: "not_permitted_by_profile",
            message: "certificate was already issued within this profile's reuse window",
          },
        }),
      ),
    );
    const onClose = vi.fn();

    render(<RevokeDialog certificate={CERTIFICATE} onClose={onClose} />);
    fireEvent.click(screen.getByRole("button", { name: /^revoke certificate$/i }));

    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "certificate was already issued within this profile's reuse window",
    );
    expect(onClose).not.toHaveBeenCalled();
    // The dialog stays interactive: the submit button is re-enabled.
    expect(
      (screen.getByRole("button", { name: /^revoke certificate$/i }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });

  it("disables both buttons while the revoke is in flight", async () => {
    let resolveInflight: (response: Response) => void = () => {};
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            resolveInflight = resolve;
          }),
      ),
    );

    const onClose = vi.fn();
    render(<RevokeDialog certificate={CERTIFICATE} onClose={onClose} />);
    fireEvent.click(screen.getByRole("button", { name: /^revoke certificate$/i }));

    expect(
      (screen.getByRole("button", { name: /^revoking/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect((screen.getByRole("button", { name: /^cancel$/i }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    resolveInflight(jsonResponse(200, REVOKE_201(CERTIFICATE.id)));
    await vi.waitFor(() => {
      // The dialog itself closes when the CALLER's onClose lands (the
      // dialog component owns neither mount nor unmount).
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  it("closes without a request on cancel", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const onClose = vi.fn();

    render(<RevokeDialog certificate={CERTIFICATE} onClose={onClose} />);
    fireEvent.click(screen.getByRole("button", { name: /^cancel$/i }));

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});