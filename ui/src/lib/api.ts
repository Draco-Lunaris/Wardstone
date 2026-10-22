// The one doorway between the SPA and the server: a same-origin fetch
// wrapper. The session is a cookie the browser sets at the `/auth/ui`
// relay and carries itself — NO token ever reaches JavaScript, so this
// client needs no auth logic whatsoever, only:
//!
//! 1. the `X-Requested-With: wardstone-ui` CSRF marker on every mutating
//!    request (GET/HEAD exempt): ws-web's proxy refuses cookie-carrying
//!    mutations without it (crates/ws-web/src/session/mod.rs), so a
//!    request the UI's own JavaScript makes must always carry it;
//! 2. ws-api's error envelope `{"error":{"code","message"}}` parsed into
//!    a typed `ApiError` — the login page keys the TOTP step on
//!    `mfa_required` and surfaces `message`s verbatim;
//! 3. the rate limiter's PLAIN-TEXT 429 (tower_governor answers
//!    `Too Many Requests! Wait for Ns` — NOT the JSON envelope; verified
//!    on the wire by Task 13) parsed into a sane `ApiError` too.

/** The name of ws-web's CSRF marker header. */
export const CSRF_HEADER_NAME = "X-Requested-With";

/** The marker value ws-web's rule demands (`session::CSRF_HEADER_VALUE`). */
export const CSRF_HEADER_VALUE = "wardstone-ui";

/** A failed request, decoded. `message` is what the server said — the
 * envelope's verbatim message, or the limiter's plain text — never a
 * paraphrase the UI invents. */
export class ApiError extends Error {
  readonly code: string;
  readonly message: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.message = message;
    this.status = status;
  }
}

/**
 * Same-origin fetch against the relay or the proxied API.
 *
 * Injects the CSRF marker on every non-GET/HEAD method. On success parses
 * the JSON body (`undefined` for a 204). On failure throws `ApiError`:
 * JSON error envelopes decode into `{code, message}` verbatim; a non-JSON
 * body (the plain-text 429 shapes tower_governor emits) becomes the body
 * text as the message with a synthetic code (`rate_limited` on 429, else
 * `http_<status>`).
 */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (method !== "GET" && method !== "HEAD" && !headers.has(CSRF_HEADER_NAME)) {
    headers.set(CSRF_HEADER_NAME, CSRF_HEADER_VALUE);
  }
  if (init.body != null && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, { ...init, headers });

  if (response.ok) {
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }

  throw await parseError(response);
}

/** Decode any failure response into an `ApiError` without ever throwing. */
async function parseError(response: Response): Promise<ApiError> {
  const status = response.status;
  const contentType = response.headers.get("Content-Type") ?? "";

  if (contentType.includes("application/json")) {
    try {
      const body: unknown = await response.json();
      const error = (body as { error?: { code?: string; message?: string } })?.error;
      if (error && typeof error === "object") {
        return new ApiError(String(error.code ?? `http_${status}`), String(error.message ?? ""), status);
      }
    } catch {
      // A malformed JSON body falls through to the plain-text handling.
    }
  }

  let message = "";
  try {
    message = (await response.text()).trim();
  } catch {
    // The body is unreadable; the generic message below still applies.
  }
  const code = status === 429 ? "rate_limited" : `http_${status}`;
  if (!message) {
    message = `the request failed with status ${status}`;
  }
  return new ApiError(code, message, status);
}