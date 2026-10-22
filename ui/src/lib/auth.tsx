// The browser session: a tiny framework-free store (`SessionStore`) plus
// a React context shell over it. The session IS the cookie — the browser
// never sees a token, so this layer's whole job is:
//
// - boot once off `GET /api/v1/auth/me` (the cookie authenticates via
//   ws-web's proxy; a 401 means unauthenticated);
// - `login` against `POST /auth/ui/login`, keying the TOTP step on the
//   `mfa_required` error code (the relay passes ws-api's envelope through
//   verbatim) and landing the MeResponse in state;
// - `logout` against `POST /auth/ui/logout` (the relay clears the cookie);
// - the OIDC button's data: `GET /auth/ui/config` (relayed, public) and a
//   redirect to `/auth/ui/oidc/<provider>/start`, a full navigation — the
//   relay hands back ws-api's 303 to the provider.
//
// House rule honored here: NO token material ever lives in JavaScript
// state. `AuthState.me` is identity only.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  type ReactNode,
  useSyncExternalStore,
} from "react";

import { ApiError, apiFetch } from "./api";

/** The identity ws-api's `me` route answers with (also the 200 body of the
 * login relay) — `null`-able fields exist for machine actors, and the UI
 * treats any missing display field as fallback-able. */
export interface MeResponse {
  actor_type: string;
  actor_id: string;
  tenant_id: string;
  capabilities: string[];
  username: string | null;
  display_name: string | null;
  role: string | null;
  mfa_enabled: boolean | null;
}

/** `GET /auth/ui/config`'s body: whether SSO is configured for login, and
 * the provider label the start route requires (ws-api resolves the start
 * route's `{provider}` against the stored row's `provider_type`, so the
 * navigator must send the right label — the flag alone is not enough). */
export interface UiAuthConfig {
  oidc_configured: boolean;
  provider: string | null;
}

export type AuthStatus = "booting" | "authenticated" | "unauthenticated";

/** One immutable snapshot of the session. Updates replace the whole
 * object (useSyncExternalStore's contract). */
export interface AuthState {
  status: AuthStatus;
  me: MeResponse | null;
  /** True after a login answered `mfa_required` — the Login page shows
   * the TOTP field. Cleared on success (password-only logins too) and on
   * any login failure that is NOT a wrong-code refusal while the step is
   * showing (login()'s MFA-step rule below). */
  mfaRequired: boolean;
  /** The current login submit: `submitting` while POST /auth/ui/login is
   * in flight (double submits are ignored), `idle` otherwise. */
  loginState: "idle" | "submitting";
  /** The last failed login, surfaced verbatim; `mfa_required` never lands
   * here (it is a step, not an error). */
  loginError: ApiError | null;
  /** The login page's SSO data; null until the page loads the config. */
  authConfig: UiAuthConfig | null;
}

const INITIAL_STATE: AuthState = {
  status: "booting",
  me: null,
  mfaRequired: false,
  loginState: "idle",
  loginError: null,
  authConfig: null,
};

/** Does this ws-api message name the SECOND-FACTOR check (the wrong-code
 * 401's wire text: "invalid multi-factor code")? The two `unauthorized`
 * login messages are ws-api's contract (routes/auth.rs), so the marker is
 * the phrase, not the status/code both flavors share. */
function isMultiFactorMessage(message: string): boolean {
  return /multi-factor|one-time|mfa|totp/i.test(message);
}

/** The session store. One instance per provider; every mutation swaps in
 * a fresh immutable snapshot and notifies subscribers. */
export class SessionStore {
  private listeners = new Set<() => void>();
  private snapshot: AuthState = INITIAL_STATE;
  private bootPromise: Promise<void> | null = null;

  get state(): AuthState {
    return this.snapshot;
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  private set(patch: Partial<AuthState>): void {
    this.snapshot = { ...this.snapshot, ...patch };
    for (const listener of this.listeners) {
      listener();
    }
  }

  /** Resolve the session exactly once per store lifetime (concurrent and
   * repeated callers share the in-flight boot). */
  bootOnce(): Promise<void> {
    this.bootPromise ??= this.boot();
    return this.bootPromise;
  }

  private async boot(): Promise<void> {
    try {
      const me = await apiFetch<MeResponse>("/api/v1/auth/me");
      this.set({ status: "authenticated", me });
    } catch {
      // ANY failure (the 401, a transport error, a 5xx) means the UI
      // cannot prove a session: land unauthenticated and let the login
      // page decide. The cookie alone decides nothing.
      this.set({ status: "unauthenticated", me: null });
    }
  }

  /** `POST /auth/ui/login`. Resolves with the store landed in its new
   * state: authenticated on success, `mfaRequired` after the challenge,
   * `loginError` carrying the verbatim failure otherwise. Rejections are
   * swallowed INTO the state — the page renders `loginError`; it never
   * needs its own catch. */
  async login(username: string, password: string, totpCode?: string): Promise<void> {
    if (this.snapshot.loginState === "submitting") {
      return;
    }
    this.set({ loginState: "submitting", loginError: null });
    try {
      const me = await apiFetch<MeResponse>("/auth/ui/login", {
        method: "POST",
        body: JSON.stringify({ username, password, totp_code: totpCode }),
      });
      // totp_code: undefined never serializes, so the first attempt sends
      // exactly {username, password} — ws-api answers mfa_required, and
      // the CHALLENGED retry adds the code.
      this.set({
        status: "authenticated",
        me,
        loginState: "idle",
        mfaRequired: false,
        loginError: null,
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === "mfa_required") {
        // ws-api demands the second factor: reveal the TOTP field. Not an
        // error — the credentials may have already been accepted once the
        // code arrives.
        this.set({ loginState: "idle", mfaRequired: true, loginError: null });
        return;
      }
      const apiError =
        error instanceof ApiError
          ? error
          : new ApiError(
              "transport",
              error instanceof Error ? error.message : "the login could not be sent",
              0,
            );
      // THE MFA-STEP RULE: a wrong TOTP code is NOT a credential rejection.
      // ws-api's wire shapes both refusals as a 401 `unauthorized` —
      // the password check answers "invalid credentials" (routes/auth.rs's
      // username/password verification), the TOTP check answers
      // "invalid multi-factor code" — so the status AND the envelope code
      // are shared and only the MESSAGE tells them apart. Once the
      // challenge is showing, the credentials were ALREADY accepted once
      // (`mfa_required` is issued only after the password verified), so a
      // further `unauthorized` whose message names the multi-factor check
      // is a wrong-code RETRY: the TOTP field STAYS ARMED and the error
      // surfaces above it. Any other failure shape resets the step:
      // "invalid credentials" (the operator re-edited the password, or the
      // account's credential state changed) must still escape the step; a
      // 429 limiter answer, a 403 lockout, a 5xx, or a transport failure
      // is not an MFA verdict at all — without a live challenge the next
      // `mfa_required` flips the field back on, and with one shown the
      // operator resubmits username + password to re-enter it.
      const keepMfaStep =
        this.snapshot.mfaRequired &&
        apiError.code === "unauthorized" &&
        isMultiFactorMessage(apiError.message);
      this.set({
        loginState: "idle",
        loginError: apiError,
        mfaRequired: keepMfaStep,
      });
    }
  }

  /** `POST /auth/ui/logout` — the relay revokes server-side and clears
   * the cookie. The local state ends unauthenticated regardless of the
   * relay's answer: the route is idempotent by design, and the UI must
   * never strand a user in a "logged-in view" after they asked out. */
  async logout(): Promise<void> {
    try {
      await apiFetch("/auth/ui/logout", { method: "POST" });
    } catch {
      // Best-effort (transport failure, 5xx): still land logged out.
    }
    this.set({
      status: "unauthenticated",
      me: null,
      mfaRequired: false,
      loginState: "idle",
      loginError: null,
    });
  }

  /** Load the SSO flag for the login page. Any failure reads as
   * not-configured — the button merely hides. */
  async loadAuthConfig(): Promise<void> {
    try {
      const config = await apiFetch<Partial<UiAuthConfig>>("/auth/ui/config");
      this.set({
        authConfig: {
          oidc_configured: config.oidc_configured === true,
          provider: typeof config.provider === "string" ? config.provider : null,
        },
      });
    } catch {
      this.set({ authConfig: { oidc_configured: false, provider: null } });
    }
  }

  /** The SSO entry: a FULL navigation, not client-side routing — the relay
   * redirects (303) straight to the provider's authorization endpoint and
   * the provider bounces back into `/auth/ui/oidc/<provider>/callback`,
   * where ws-web mints the cookie session. */
  startOidc(): void {
    const provider = this.snapshot.authConfig?.provider;
    if (!provider) {
      return;
    }
    window.location.assign(`/auth/ui/oidc/${encodeURIComponent(provider)}/start`);
  }
}

const SessionContext = createContext<SessionStore | null>(null);

/** Boots the session on mount and hands the store down. One per app. */
export function SessionProvider({ children }: { children: ReactNode }) {
  const store = useMemo(() => new SessionStore(), []);
  const booted = useRef(false);
  useEffect(() => {
    if (!booted.current) {
      booted.current = true;
      void store.bootOnce();
    }
  }, [store]);
  return <SessionContext.Provider value={store}>{children}</SessionContext.Provider>;
}

/** The store itself (stable identity). */
export function useSession(): SessionStore {
  const store = useContext(SessionContext);
  if (!store) {
    throw new Error("useSession must be used inside <SessionProvider>");
  }
  return store;
}

/** The current AuthState snapshot, re-rendering on every store change. */
export function useAuthState(): AuthState {
  const store = useSession();
  const getState = useCallback(() => store.state, [store]);
  return useSyncExternalStore(store.subscribe, getState, getState);
}