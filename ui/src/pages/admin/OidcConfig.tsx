// The OIDC provider-configuration form (crates/ws-api/src/routes/oidc.rs):
// the gated `GET/PUT/DELETE /api/v1/oidc/config` surface plus the
// discovery "test" button. The stored secret NEVER reaches this page —
// the read response carries `client_secret_set` only, the field holds the
// NEW secret only while the operator types it, and an unchanged save maps
// the field to the ABSENT key so the server keeps what it stored. On a
// first configuration the secret is required (refused client-side with
// the server's own 400 wording, before any request leaves the page).
//
// The test button always sends a WELL-FORMED override body: Task 5's
// deferred T5-M1 means a malformed override is read by the server as "no
// override", probing the SAVED configuration instead — the helper text
// tells the operator to distrust a pass whose endpoints don't belong to
// the provider they meant.

import { useEffect, useState, type FormEvent, type ChangeEvent } from "react";

import { ApiError } from "../../lib/api";
import {
  OIDC_PROVIDER_TYPES,
  buildOidcPayload,
  buildOidcTestOverride,
  fetchOidcConfig,
  redirectUriPlaceholder,
  removeOidcConfig,
  saveOidcConfig,
  testOidcConfig,
  type OidcConfig,
  type OidcDiscovery,
  type OidcFormFields,
} from "../../lib/admin";
import { hasCapability } from "../../lib/certs";
import { useAuthState } from "../../lib/auth";

const BLANK_FIELDS: OidcFormFields = {
  provider_type: "keycloak",
  display_name: "",
  discovery_url: "",
  client_id: "",
  client_secret: "",
  redirect_uri: "",
  scopes: "openid profile email",
};

function fieldsOf(config: OidcConfig): OidcFormFields {
  return {
    provider_type: config.provider_type,
    display_name: config.display_name,
    discovery_url: config.discovery_url,
    client_id: config.client_id,
    client_secret: "",
    redirect_uri: config.redirect_uri,
    scopes: config.scopes,
  };
}

function toApiError(caught: unknown, fallback: string): ApiError {
  return caught instanceof ApiError
    ? caught
    : new ApiError("transport", caught instanceof Error ? caught.message : fallback, 0);
}

export default function OidcConfig() {
  const auth = useAuthState();
  // The capability, as a STABLE boolean — depending on the identity object
  // itself would re-run the load on every render (a fresh snapshot each
  // time), looping the GET.
  const canManage = hasCapability(auth.me?.capabilities, "manage_system");
  const [loaded, setLoaded] = useState<"loading" | "ready" | "error">("loading");
  const [loadError, setLoadError] = useState<ApiError | null>(null);
  const [config, setConfig] = useState<OidcConfig | null>(null);
  const [form, setForm] = useState<OidcFormFields>(BLANK_FIELDS);
  const [formError, setFormError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [discovery, setDiscovery] = useState<OidcDiscovery | null>(null);
  const [testError, setTestError] = useState<ApiError | null>(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    if (!canManage) {
      return; // No manage_system: the server would 403 the whole surface.
    }
    let cancelled = false;
    fetchOidcConfig()
      .then((existing) => {
        if (cancelled) return;
        setConfig(existing);
        setForm(existing ? fieldsOf(existing) : BLANK_FIELDS);
        setLoaded("ready");
      })
      .catch((caught) => {
        if (cancelled) return;
        setLoadError(toApiError(caught, "the configuration could not be loaded"));
        setLoaded("error");
      });
    return () => {
      cancelled = true;
    };
  }, [canManage]);

  if (!hasCapability(auth.me?.capabilities, "manage_system")) {
    return (
      <section>
        <h2>SSO provider (OIDC)</h2>
        <p className="muted">
          Your account does not hold the manage_system capability, so it cannot view or change
          the OIDC provider configuration.
        </p>
      </section>
    );
  }

  const set = (key: keyof OidcFormFields) => (event: ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setForm((previous) => ({ ...previous, [key]: event.target.value }));
  };

  const onSave = async (event: FormEvent) => {
    event.preventDefault();
    if (saving) {
      return;
    }
    setFormError(null);
    setApiError(null);
    setNotice(null);
    const { body, error } = buildOidcPayload(form, config?.client_secret_set ?? false);
    if (error || body === null) {
      // Client-side refusal: die here, never on the wire.
      setFormError(error ?? "the form could not be read");
      return;
    }
    setSaving(true);
    try {
      const saved = await saveOidcConfig(body);
      setConfig(saved);
      setForm(fieldsOf(saved));
      setNotice("Saved the provider configuration.");
    } catch (caught) {
      setApiError(toApiError(caught, "the configuration could not be saved"));
    } finally {
      setSaving(false);
    }
  };

  const onTest = async () => {
    if (testing) {
      return;
    }
    setTestError(null);
    setDiscovery(null);
    setTesting(true);
    try {
      const result = await testOidcConfig(buildOidcTestOverride(form));
      setDiscovery(result);
    } catch (caught) {
      setTestError(toApiError(caught, "the discovery probe could not be sent"));
    } finally {
      setTesting(false);
    }
  };

  const onRemove = async () => {
    setApiError(null);
    setNotice(null);
    try {
      await removeOidcConfig();
      setConfig(null);
      setForm(BLANK_FIELDS);
      setDiscovery(null);
      setNotice("SSO provider removed — OIDC sign-in is disabled.");
    } catch (caught) {
      setApiError(toApiError(caught, "the configuration could not be removed"));
    }
  };

  if (loaded === "loading") {
    return (
      <section>
        <h2>SSO provider (OIDC)</h2>
        <p className="muted">Loading…</p>
      </section>
    );
  }
  if (loaded === "error") {
    return (
      <section>
        <h2>SSO provider (OIDC)</h2>
        <p className="error-panel" role="alert">
          {loadError?.message}
        </p>
      </section>
    );
  }

  const isNew = config === null;
  const placeholder = redirectUriPlaceholder(form.provider_type);

  return (
    <section>
      <h2>SSO provider (OIDC)</h2>
      {isNew ? (
        <p className="muted">
          No provider is configured — OIDC sign-in is off for this tenant. Fill the form to enable
          it; your account keeps its password sign-in throughout.
        </p>
      ) : (
        <p className="muted">
          The provider below backs the login page's "Sign in with SSO" button. The stored secret is
          never displayed here — only that it exists.
        </p>
      )}

      {notice && <p className="notice">{notice}</p>}
      {apiError && (
        <p className="error-panel" role="alert">
          {apiError.message}
        </p>
      )}
      {formError && (
        <p className="error-panel" role="alert">
          {formError}
        </p>
      )}

      <form onSubmit={onSave} aria-label="OIDC provider configuration">
        <label htmlFor="oidc-provider-type">Provider type</label>
        <select id="oidc-provider-type" value={form.provider_type} onChange={set("provider_type")}>
          {OIDC_PROVIDER_TYPES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <label htmlFor="oidc-display-name">Display name</label>
        <input
          id="oidc-display-name"
          value={form.display_name}
          onChange={set("display_name")}
          placeholder="e.g. the organization SSO"
        />

        <label htmlFor="oidc-discovery-url">Discovery URL</label>
        <input
          id="oidc-discovery-url"
          value={form.discovery_url}
          onChange={set("discovery_url")}
          placeholder="https://idp.example.test/.well-known/openid-configuration"
        />

        <label htmlFor="oidc-client-id">Client ID</label>
        <input id="oidc-client-id" value={form.client_id} onChange={set("client_id")} />

        <label htmlFor="oidc-client-secret">Client secret</label>
        <input
          id="oidc-client-secret"
          type="password"
          value={form.client_secret}
          onChange={set("client_secret")}
          placeholder={isNew ? "Required for a new configuration" : "keep existing"}
          autoComplete="new-password"
        />

        <label htmlFor="oidc-redirect-uri">Redirect URI</label>
        <input
          id="oidc-redirect-uri"
          value={form.redirect_uri}
          onChange={set("redirect_uri")}
          placeholder={placeholder}
        />
        <p className="muted">
          Must be https; use{" "}
          <code>{placeholder}</code> — the host this Wardstone instance is reached at.
        </p>

        <label htmlFor="oidc-scopes">Scopes</label>
        <input
          id="oidc-scopes"
          value={form.scopes}
          onChange={set("scopes")}
          placeholder="openid profile email"
        />

        <div className="dialog-actions">
          <button type="submit" disabled={saving}>
            {saving ? "Saving…" : "Save configuration"}
          </button>
          <button type="button" onClick={onTest} disabled={testing}>
            {testing ? "Probing…" : "Test discovery"}
          </button>
          {!isNew && (
            <button type="button" className="danger" onClick={onRemove}>
              Remove provider configuration
            </button>
          )}
        </div>
      </form>

      <p className="muted">
        Test discovery probes the values currently in the form (the saved configuration only after a
        reload). Treat a pass with unexpected endpoints with suspicion — it may be answering from the
        saved configuration rather than your edits — and confirm the issuer line below belongs to the
        provider you meant before trusting it. A failed probe reports the provider's answer verbatim.
      </p>

      {testError && (
        <p className="error-panel" role="alert">
          {testError.message}
        </p>
      )}
      {discovery && (
        <div className="subpanel" aria-label="Discovery result">
          <h3>Discovery answered</h3>
          <dl className="detail-grid">
            <dt>Issuer</dt>
            <dd>{discovery.issuer}</dd>
            <dt>Authorization endpoint</dt>
            <dd>{discovery.authorization_endpoint}</dd>
            <dt>Token endpoint</dt>
            <dd>{discovery.token_endpoint}</dd>
            <dt>JWKS URI</dt>
            <dd>{discovery.jwks_uri}</dd>
          </dl>
        </div>
      )}
    </section>
  );
}