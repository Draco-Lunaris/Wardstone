// The certificates lib layer's pins (Task 15, tests first):
//
// 1. THE QUERY STRING BUILDER — every list filter arrives at the wire as
//    a URLSearchParams-encoded query (Task 2's encoding discipline: names
//    with spaces, `&`, `=`, and `?` must survive verbatim; empty axes are
//    OMITTED, never sent as empty strings; page 0 is meaningful and
//    page_size uses the wire's snake_case spelling).
// 2. THE REVOKE PAYLOAD BUILDER — the typed reason serializes as its
//    exact snake_case name (the string ws-worker's CRL/OCSP builders
//    parse); the free-text detail is trimmed, and empty or whitespace
//    detail is OMITTED from the JSON entirely (never `""`, never `null`).
// 3. THE ONE-TIME-DOWNLOAD MEMORY CONTRACT — the generated private key's
//    blob URL is created exactly once, revoked exactly once (the
//    component's unmount cleanup calls `revoke()`), and a download after
//    the revoke is refused rather than resurrecting the URL.
// 4. Small pure helpers: capability checks (the role-gating discipline)
//    and SAN text parsing.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  buildCertificateListQuery,
  buildRevokePayload,
  fetchCertificates,
  fetchCertificatesSlim,
  fetchText,
  makeOneTimeDownload,
  parseSans,
  parseAiaUris,
  REVOCATION_REASONS,
  hasCapability,
} from "./certs";
import { ApiError } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("buildCertificateListQuery", () => {
  it("builds every axis with URLSearchParams encoding, snake_case page_size", () => {
    const caId = "0f1e2d3c-0000-4000-8000-000000000000";
    const qs = buildCertificateListQuery({
      status: "revoked",
      profile: "Web Servers",
      ca: caId,
      q: "CN=a&b=c?d",
      page: 2,
      pageSize: 50,
    });

    // The exact wire string: spaces as +, `&` `=` `?` percent-encoded.
    expect(qs).toBe(
      `status=revoked&profile=Web+Servers&ca=${caId}` +
        `&q=CN%3Da%26b%3Dc%3Fd&page=2&page_size=50`,
    );

    // …and it decodes back to exactly what the operator typed.
    const back = new URLSearchParams(qs);
    expect(back.get("profile")).toBe("Web Servers");
    expect(back.get("q")).toBe("CN=a&b=c?d");
    expect(back.get("page_size")).toBe("50");
  });

  it("emits an empty string when nothing is filtered", () => {
    expect(buildCertificateListQuery({})).toBe("");
  });

  it("omits empty-string axes instead of sending them as empty values", () => {
    const qs = buildCertificateListQuery({ status: "", profile: "", q: "" });
    expect(qs).toBe("");
    expect(qs).not.toBe("status=&profile=&q=");
  });

  it("keeps page 0 (the first page) when it is set explicitly", () => {
    expect(buildCertificateListQuery({ page: 0, pageSize: 25 })).toBe(
      "page=0&page_size=25",
    );
  });
});

describe("fetchCertificates", () => {
  it("appends the built query to the list route", async () => {
    const fetchMock = vi.fn(async () =>
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const rows = await fetchCertificates({ status: "active", page: 1 });
    expect(rows).toEqual([]);
    const [path] = fetchMock.mock.calls[0] as unknown as [string];
    expect(path).toBe("/api/v1/certificates?status=active&page=1");
  });

  it("uses a bare route (no trailing ?) when nothing is filtered", async () => {
    const fetchMock = vi.fn(async () =>
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await fetchCertificates({});
    const [path] = fetchMock.mock.calls[0] as unknown as [string];
    expect(path).toBe("/api/v1/certificates");
  });
});

describe("fetchCertificatesSlim", () => {
  it("hits the slim route with the sieve's query axes", async () => {
    const fetchMock = vi.fn(async () =>
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const rows = await fetchCertificatesSlim({ status: "active", pageSize: 500 });
    expect(rows).toEqual([]);
    const [path] = fetchMock.mock.calls[0] as unknown as [string];
    // The dashboard sieve's exact wire request.
    expect(path).toBe("/api/v1/certificates/slim?status=active&page_size=500");
  });

  it("keeps page 0 and answers the bare route when nothing is filtered", async () => {
    const fetchMock = vi.fn(async () =>
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await fetchCertificatesSlim({ page: 0 });
    const [paged] = fetchMock.mock.calls[0] as unknown as [string];
    expect(paged).toBe("/api/v1/certificates/slim?page=0");
    await fetchCertificatesSlim({});
    const [bare] = fetchMock.mock.calls[1] as unknown as [string];
    expect(bare).toBe("/api/v1/certificates/slim");
  });
});

describe("buildRevokePayload", () => {
  it("trims the free-text detail", () => {
    const payload = buildRevokePayload(
      "key_compromise",
      "  laptop left in the rain  ",
    );
    expect(payload).toEqual({
      reason: "key_compromise",
      detail: "laptop left in the rain",
    });
  });

  it("omits the detail key entirely when it is empty, blank, or absent", () => {
    for (const detail of [undefined, "", "   \n\t "]) {
      const payload = buildRevokePayload("superseded", detail);
      expect("detail" in payload).toBe(false);
    }
    // The serialized body carries the reason ALONE — never detail: "" or null.
    expect(JSON.stringify(buildRevokePayload("superseded", ""))).toBe(
      '{"reason":"superseded"}',
    );
  });

  it("serializes all nine reasons as their exact snake_case names", () => {
    const expected = [
      "unspecified",
      "key_compromise",
      "ca_compromise",
      "affiliation_changed",
      "superseded",
      "cessation_of_operation",
      "certificate_hold",
      "privilege_withdrawn",
      "aa_compromise",
    ];
    expect([...REVOCATION_REASONS]).toEqual(expected);
    for (const reason of REVOCATION_REASONS) {
      expect(JSON.stringify(buildRevokePayload(reason, undefined))).toBe(
        `{"reason":"${reason}"}`,
      );
    }
  });
});

describe("makeOneTimeDownload (the generated-key memory contract)", () => {
  let revokeCalls: string[];
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;

  beforeEach(() => {
    revokeCalls = [];
    let next = 0;
    URL.createObjectURL = vi.fn(() => `blob:mock-${next++}`);
    URL.revokeObjectURL = vi.fn((url: string) => {
      revokeCalls.push(url);
    });
  });

  afterEach(() => {
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  });

  it("creates exactly one blob URL from the key material and hands it back", () => {
    const one = makeOneTimeDownload("-----PRIVATE KEY-----", "text/plain", "key.pem");
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(one.blobUrl).toMatch(/^blob:mock-/);
    expect(one.filename).toBe("key.pem");
    const [blob] = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock
      .calls[0] as unknown as [Blob];
    expect(blob).toBeInstanceOf(Blob);
  });

  it("revokes that URL exactly once across repeated revoke calls (the unmount cleanup)", () => {
    const one = makeOneTimeDownload("key", "text/plain", "key.pem");
    one.revoke();
    one.revoke();
    one.revoke();
    expect(revokeCalls).toEqual([one.blobUrl]);
  });

  it("refuses to download after the revoke instead of resurrecting the URL", () => {
    // jsdom cannot perform a real navigation on anchor click, so the
    // download path is not observed here — the contract under test is
    // that a download AFTER the revoke does not throw and does not
    // create (or re-create) any object URL.
    const one = makeOneTimeDownload("key", "text/plain", "key.pem");
    one.revoke();
    expect(revokeCalls).toEqual([one.blobUrl]);
    expect(() => one.download()).not.toThrow();
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(revokeCalls).toEqual([one.blobUrl]);
  });
});

describe("hasCapability", () => {
  it("matches snake_case capability names and tolerates a missing identity", () => {
    const caps = ["issue", "read_certificates"];
    expect(hasCapability(caps, "issue")).toBe(true);
    expect(hasCapability(caps, "generate_leaf_key")).toBe(false);
    expect(hasCapability(undefined, "issue")).toBe(false);
  });
});

describe("parseSans", () => {
  it("splits textarea lines, trims, and drops blanks", () => {
    expect(parseSans("vpn.example.com\n\n  api.example.com  \n\t\nweb.example.com")).toEqual([
      "vpn.example.com",
      "api.example.com",
      "web.example.com",
    ]);
    expect(parseSans("")).toEqual([]);
    expect(parseSans("   ")).toEqual([]);
  });

  it("keeps IP literals as plain strings (the server classifies DNS vs IP)", () => {
    expect(parseSans("10.0.0.5\n2001:db8::1")).toEqual(["10.0.0.5", "2001:db8::1"]);
  });
});

describe("fetchText (the chain route's non-JSON body)", () => {
  it("returns the raw text body on success (application/x-pem-file is not JSON)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response("-----BEGIN CERTIFICATE-----\nA\nB\n", {
          status: 200,
          headers: { "content-type": "application/x-pem-file" },
        }),
      ),
    );
    const pem = await fetchText("/api/v1/certificates/x/chain");
    expect(pem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
  });

  it("parses a JSON error envelope into ApiError verbatim", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            error: { code: "not_permitted_by_profile", message: "no" },
          }),
          { status: 400, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const err = await errorOf(fetchText("/api/v1/certificates/x/chain"));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe("not_permitted_by_profile");
    expect(err.message).toBe("no");
    expect(err.status).toBe(400);
  });

  it("falls back to the plain text body for non-JSON errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response("certificate not found", {
          status: 404,
          headers: { "content-type": "text/plain" },
        }),
      ),
    );
    const err = await errorOf(fetchText("/api/v1/certificates/x/chain"));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe("http_404");
    expect(err.message).toBe("certificate not found");
  });
});

async function errorOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("the call unexpectedly succeeded");
}

// The AIA (authority information access) field-only parser. The fixture
// PEMs below are REAL certificates — self-signed test-authoring-time
// builds (openssl 3.0.13, ed25519), the first carrying an
// authorityInfoAccess extension with one OCSP and one caIssuers URI, the
// second carrying none (ws-ca's test suite generates its certs at
// runtime, so no static fixture existed to copy; these stand in).
const FIXTURE_WITH_AIA_PEM = `-----BEGIN CERTIFICATE-----
MIIBqjCCAVygAwIBAgIUGcuWCnYcSiJ07/hMDXpAFvw7iAswBQYDK2VwMCExHzAd
BgNVBAMMFndhcmRzdG9uZS1maXh0dXJlLXRlc3QwHhcNMjYxMDIyMTk0ODA4WhcN
MjYxMTIxMTk0ODA4WjAhMR8wHQYDVQQDDBZ3YXJkc3RvbmUtZml4dHVyZS10ZXN0
MCowBQYDK2VwAyEARHdkIwO4DmAxojM5Y37xHmmPQ1tjuCt8UC1psPNQgJCjgaUw
gaIwDAYDVR0TBAUwAwEB/zBzBggrBgEFBQcBAQRnMGUwMAYIKwYBBQUHMAGGJGh0
dHA6Ly9vY3NwLndhcmRzdG9uZS50ZXN0L3Jlc3BvbmRlcjAxBggrBgEFBQcwAoYl
aHR0cDovL29jc3Aud2FyZHN0b25lLnRlc3QvaXNzdWVyLmNydDAdBgNVHQ4EFgQU
VokyUeyGEfXXq+gFWyJXQBS+3JswBQYDK2VwA0EAMs+WwgeKQ1ETYKs8uww0Peyi
zUt6yeT3ekmUbuaXo7YblM18EJbeKHcl+pGdNTESh+7+2lJCfsvnLZStWWL0Dw==
-----END CERTIFICATE-----`;

const FIXTURE_PLAIN_PEM = `-----BEGIN CERTIFICATE-----
MIIBNDCB56ADAgECAhQjs939PNTcWw3CWGdCwJ63ZClXOTAFBgMrZXAwIjEgMB4G
A1UEAwwXd2FyZHN0b25lLXBsYWluLWZpeHR1cmUwHhcNMjYxMDIyMTk0OTI1WhcN
MjYxMTIxMTk0OTI1WjAiMSAwHgYDVQQDDBd3YXJkc3RvbmUtcGxhaW4tZml4dHVy
ZTAqMAUGAytlcAMhAAesyWPH4Gcyj9PGIUffA1R/fXVurAVDlI9zGnsUgQRkoy8w
LTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBQKWXjApipDaLCdWHgVgQ2iZa241DAF
BgMrZXADQQDnmo0iRRCnDhvq7TaBMe9zWlwiklZZYxre8ZRfuh1WQ+Iv7ZHcbUMG
CfPYcJKu2WahMififl/qIB99L/eEnpUG
-----END CERTIFICATE-----`;

describe("parseAiaUris", () => {
  it("extracts the OCSP and caIssuers URIs with their method OIDs", () => {
    expect(parseAiaUris(FIXTURE_WITH_AIA_PEM)).toEqual([
      { method: "1.3.6.1.5.5.7.48.1", uri: "http://ocsp.wardstone.test/responder" },
      { method: "1.3.6.1.5.5.7.48.2", uri: "http://ocsp.wardstone.test/issuer.crt" },
    ]);
  });

  it("returns no entries for a certificate without the AIA extension", () => {
    expect(parseAiaUris(FIXTURE_PLAIN_PEM)).toEqual([]);
  });

  it("returns no entries for non-PEM input", () => {
    expect(parseAiaUris("garbage")).toEqual([]);
    expect(parseAiaUris("-----BEGIN CERTIFICATE-----\\nnot base64\\n-----END CERTIFICATE-----")).toEqual(
      [],
    );
  });
});