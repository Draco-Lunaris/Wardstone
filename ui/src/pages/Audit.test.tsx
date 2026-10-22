// The Audit filter form's render states (Task 16's sanctioned render-test
// surface): the three filter axes are all present; the first page loads
// unfiltered; Apply submits Z-suffix instants (never +00:00) and page 0;
// Reset clears the form and the query; a server error surfaces verbatim.
//
// The datetime-local inputs are browser-sanitized (a browser never
// yields a garbage value — the lib tests pin `rfc3339Z`'s null path for
// the belt-and-braces guard instead). `lib/auth` is mocked to a
// read_audit-holding account; the page gates on the capability exactly
// as production does.

declare const process: { env: Record<string, string | undefined> };

process.env.TZ = "UTC";

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Audit from "./Audit";

vi.mock("../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: { actor_id: "alice", tenant_id: "t", capabilities: ["read_audit"] },
  }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function stubFetch(responses: Array<Response>) {
  const mock = vi.fn(async (_input: RequestInfo | URL) => responses[0] ?? new Response(JSON.stringify([])));
  vi.stubGlobal("fetch", mock);
  return mock;
}

function okList() {
  return new Response(JSON.stringify([]), { status: 200 });
}

describe("Audit", () => {
  it("renders the From/To/Action filters and fetches the first page", () => {
    const fetchMock = stubFetch([okList()]);
    render(<Audit />);

    expect(screen.getByLabelText("From")).toBeTruthy();
    expect(screen.getByLabelText("To")).toBeTruthy();
    expect(screen.getByLabelText("Action")).toBeTruthy();
    // The initial unfiltered query carries the snake_case page_size.
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/v1/audit?page=0&page_size=50");
  });

  it("submits Z-suffix RFC 3339 instants (never +00:00) and resets to page 0", () => {
    const fetchMock = stubFetch([okList()]);
    render(<Audit />);

    fireEvent.change(screen.getByLabelText("From"), {
      target: { value: "2026-10-01T00:00:00" },
    });
    fireEvent.change(screen.getByLabelText("Action"), {
      target: { value: " cert_issued " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    const submitted = String(fetchMock.mock.calls[1][0]);
    expect(submitted).toBe(
      "/api/v1/audit?from=2026-10-01T00%3A00%3A00.000Z&action=cert_issued&page=0&page_size=50",
    );
    expect(submitted).not.toContain("+");
  });

  it("Reset restores the unfiltered first-page query", () => {
    const fetchMock = stubFetch([okList()]);
    render(<Audit />);

    fireEvent.change(screen.getByLabelText("Action"), {
      target: { value: "key_generated" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    fireEvent.click(screen.getByRole("button", { name: "Reset" }));

    expect(String(fetchMock.mock.calls[2][0])).toBe("/api/v1/audit?page=0&page_size=50");
  });

  it("surfaces a server error verbatim", async () => {
    stubFetch([
      new Response(
        JSON.stringify({ error: { code: "bad_request", message: "a malformed datetime" } }),
        { status: 400, headers: { "content-type": "application/json" } },
      ),
    ]);
    render(<Audit />);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("a malformed datetime");
  });
});