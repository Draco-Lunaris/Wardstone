// The login page: the single-column centered card on a plain background
// (the wireframe's "clean and boring; the data is the design"). Password
// form; the TOTP field appears only after the session store saw a
// `mfa_required` answer; the SSO button appears only when the relayed
// config says OIDC is configured. Errors render ws-api's message VERBATIM.

import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";

import { useAuthState, useSession } from "../lib/auth";

export default function Login() {
  const session = useSession();
  const state = useAuthState();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");

  // The SSO flag is the login page's own data, fetched once on mount.
  useEffect(() => {
    void session.loadAuthConfig();
  }, [session]);

  const submitting = state.loginState === "submitting";

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (submitting) return;
    await session.login(username, password, totp.trim() || undefined);
    if (session.state.status === "authenticated") {
      navigate("/", { replace: true });
    }
  };

  const showSso = state.authConfig?.oidc_configured === true && state.authConfig.provider !== null;

  return (
    <main className="login-screen">
      <div className="login-card">
        <h1 className="login-title">Wardstone</h1>
        <h2 className="login-subtitle">Sign in to the certificate authority</h2>

        {state.loginError && (
          <p className="login-error" role="alert">
            {state.loginError.message}
          </p>
        )}

        <form onSubmit={onSubmit}>
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
            autoFocus
          />

          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />

          {state.mfaRequired && (
            <>
              <label htmlFor="login-totp">One-time code (TOTP)</label>
              <input
                id="login-totp"
                name="totp_code"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={totp}
                onChange={(event) => setTotp(event.target.value)}
                placeholder="123 456"
              />
            </>
          )}

          <button type="submit" className="primary" disabled={submitting}>
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>

        {showSso && (
          <button
            type="button"
            className="secondary"
            onClick={() => session.startOidc()}
            disabled={submitting}
          >
            Sign in with SSO
          </button>
        )}
      </div>
    </main>
  );
}