// The tokens view: the service identities and their API tokens, plus the
// one-shot tokens. The three wire capabilities split the affordances
// exactly (crates/ws-api/src/routes/credentials.rs):
//
//   read_service_identities   → both LISTS
//   manage_api_tokens         → mint / revoke a service identity
//   manage_one_shot_tokens    → mint a one-shot token
//
// House rule honored here: a mint's token plaintext reaches JavaScript
// only inside the 201 response, is shown ONCE for a copy, and is GONE
// the moment the operator dismisses the reveal or leaves the page —
// never stored, never logged, never shown in any list afterwards. The
// mint capability checkboxes offer only the capabilities the signed-in
// actor itself holds: the server caps the grant at the creator's set
// anyway, so the UI never tempts an offer the mint would refuse.

import { useEffect, useRef, useState, type FormEvent } from "react";

import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import { hasCapability } from "../lib/certs";
import {
  buildOneShotPayload,
  buildServiceIdentityPayload,
  createOneShotToken,
  createServiceIdentity,
  fetchOneShotTokens,
  fetchServiceIdentities,
  isValidOneShotTtl,
  ONE_SHOT_TTL_MAX_MINUTES,
  ONE_SHOT_TTL_MIN_MINUTES,
  revokeServiceIdentity,
  type OneShotToken,
  type OneShotTokenCreated,
  type ServiceIdentity,
  type ServiceIdentityCreated,
} from "../lib/tokens";

const PAGE_SIZE = 50;
const DEFAULT_TTL_MINUTES = 60; // the server's own default

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export default function Tokens() {
  const auth = useAuthState();
  const canRead = hasCapability(auth.me?.capabilities, "read_service_identities");
  const canManage = hasCapability(auth.me?.capabilities, "manage_api_tokens");
  const canOneShot = hasCapability(auth.me?.capabilities, "manage_one_shot_tokens");

  if (!canRead && !canManage && !canOneShot) {
    return (
      <main className="page-view">
        <h1>Service identities &amp; one-shot tokens</h1>
        <p className="muted">
          Your account holds none of read_service_identities, manage_api_tokens, or
          manage_one_shot_tokens, so it cannot view or mint credentials.
        </p>
      </main>
    );
  }

  return (
    <main className="page-view">
      <h1>Service identities &amp; one-shot tokens</h1>
      {canManage && (
        <ServiceIdentitySection identityListAllowed={canRead} ownCapabilities={auth.me?.capabilities ?? []} />
      )}
      {canOneShot && <OneShotSection listAllowed={canRead} />}
      {canRead && !canManage && (
        <section className="subpanel">
          <h2>Service identities</h2>
          <IdentityList manageAllowed={false} />
        </section>
      )}
      {canRead && !canOneShot && (
        <section className="subpanel">
          <h2>One-shot tokens</h2>
          <OneShotList />
        </section>
      )}
    </main>
  );
}

/** The full service-identity surface: list + mint form. Rendered only
 * behind `manage_api_tokens`. */
function ServiceIdentitySection({
  identityListAllowed,
  ownCapabilities,
}: {
  identityListAllowed: boolean;
  ownCapabilities: string[];
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  // Checked-capability state rides the actor's own set (the server caps
  // the grant there — the UI never offers what the creator lacks).
  const [chosen, setChosen] = useState<Record<string, boolean>>({});
  const [submitting, setSubmitting] = useState(false);
  const [mintError, setMintError] = useState<ApiError | null>(null);
  const [revealed, setRevealed] = useState<ServiceIdentityCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokedId, setRevokedId] = useState<string | null>(null);
  const [revokedError, setRevokedError] = useState<ApiError | null>(null);
  // Forces the list to refetch after a successful mint or revoke (the
  // list itself lives in <IdentityList>; a bumped key remounts it).
  const [listNonce, setListNonce] = useState(0);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (submitting || name.trim() === "") {
      return;
    }
    setSubmitting(true);
    setMintError(null);
    setCopied(false);
    try {
      const capabilities = ownCapabilities.filter((capability) => chosen[capability]);
      const created = await createServiceIdentity(
        buildServiceIdentityPayload(name, description, capabilities),
      );
      setRevealed(created);
      setName("");
      setDescription("");
      setChosen({});
      setListNonce((nonce) => nonce + 1);
    } catch (caught) {
      setMintError(
        caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
      );
    } finally {
      setSubmitting(false);
    }
  };

  const revoke = async (id: string) => {
    setRevokedId(id);
    setRevokedError(null);
    try {
      await revokeServiceIdentity(id);
      setListNonce((nonce) => nonce + 1);
    } catch (caught) {
      setRevokedError(
        caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
      );
    } finally {
      setRevokedId(null);
    }
  };

  return (
    <section className="subpanel">
      <h2>Service identities</h2>
      {identityListAllowed ? (
        <IdentityList
          key={listNonce}
          manageAllowed
          revokingId={revokedId}
          onRevokedError={revokedError}
          onRevoke={revoke}
        />
      ) : (
        <p className="muted">
          Your account cannot list identities (read_service_identities missing) but can mint
          them.
        </p>
      )}

      <form onSubmit={onSubmit} aria-label="Mint a service identity">
        <h3>Mint an API token</h3>
        <label>
          Name
          <input value={name} onChange={(event) => setName(event.target.value)} required />
        </label>
        <label>
          Description
          <input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="who runs it, against what"
          />
        </label>
        <fieldset>
          <legend>Capabilities (the server caps this grant at your own set)</legend>
          {ownCapabilities.length === 0 && (
            <p className="muted">Your account holds no capabilities to delegate.</p>
          )}
          {ownCapabilities.map((capability) => (
            <label key={capability} className="cap-check">
              <input
                type="checkbox"
                checked={chosen[capability] ?? false}
                onChange={(event) =>
                  setChosen((current) => ({ ...current, [capability]: event.target.checked }))
                }
              />
              {capability}
            </label>
          ))}
        </fieldset>
        {mintError && (
          <p className="error-panel" role="alert">
            {mintError.message}
          </p>
        )}
        <button type="submit" disabled={submitting || name.trim() === ""}>
          {submitting ? "Minting…" : "Mint token"}
        </button>
      </form>
      {revealed && (
        <TokenReveal
          token={revealed.token}
          caption={`${revealed.name} — minted ${formatDate(revealed.created_at)}`}
          onDismiss={() => setRevealed(null)}
          copied={copied}
          onCopied={() => setCopied(true)}
        />
      )}
    </section>
  );
}

/** The identities list (read_service_identities). Keyed remounts give a
 * plain refetch discipline after mints and revokes. */
function IdentityList({
  manageAllowed,
  revokingId = null,
  onRevokedError = null,
  onRevoke,
}: {
  manageAllowed: boolean;
  revokingId?: string | null;
  onRevokedError?: ApiError | null;
  onRevoke?: (id: string) => Promise<void>;
}) {
  const [rows, setRows] = useState<ServiceIdentity[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchServiceIdentities({ pageSize: PAGE_SIZE })
      .then((list) => {
        if (!cancelled) setRows(list);
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(
            caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      {onRevokedError && (
        <p className="error-panel" role="alert">
          {onRevokedError.message}
        </p>
      )}
      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {rows === null && !error && <p className="muted">Loading…</p>}
      {rows !== null && rows.length === 0 && !error && (
        <p className="muted">No service identities exist yet.</p>
      )}
      {rows !== null && rows.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Capabilities</th>
              <th>State</th>
              <th>Created</th>
              {manageAllowed && <th aria-label="Actions" />}
            </tr>
          </thead>
          <tbody>
            {rows.map((identity) => (
              <tr key={identity.id} className="cert-row">
                <td>
                  {identity.name}
                  {identity.description && (
                    <span className="muted"> — {identity.description}</span>
                  )}
                </td>
                <td>{identity.capabilities.join(", ") || <span className="muted">none</span>}</td>
                <td>
                  <span
                    className={`status-badge ${identity.revoked_at ? "status-revoked" : "status-active"}`}
                  >
                    {identity.revoked_at ? "revoked" : "active"}
                  </span>
                </td>
                <td>{formatDate(identity.created_at)}</td>
                {manageAllowed && (
                  <td>
                    {!identity.revoked_at && (
                      <button
                        type="button"
                        className="danger"
                        disabled={revokingId === identity.id}
                        onClick={() => onRevoke?.(identity.id)}
                      >
                        {revokingId === identity.id ? "Revoking…" : "Revoke"}
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** The one-shot surface: list + TTL-bounded mint. Rendered only behind
 * `manage_one_shot_tokens`. */
function OneShotSection({ listAllowed }: { listAllowed: boolean }) {
  const [ttlText, setTtlText] = useState(String(DEFAULT_TTL_MINUTES));
  const [submitting, setSubmitting] = useState(false);
  const [mintError, setMintError] = useState<ApiError | null>(null);
  const [revealed, setRevealed] = useState<OneShotTokenCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [listNonce, setListNonce] = useState(0);

  const ttl = Number(ttlText);
  const ttlValid = buildOneShotPayload(ttl) !== null;

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    // The client refuses out-of-bounds windows before the wire does (the
    // server's own bad_request answers verbatim below if anything slips).
    if (submitting || !ttlValid || !isValidOneShotTtl(Number(ttl))) {
      return;
    }
    setSubmitting(true);
    setMintError(null);
    setCopied(false);
    try {
      const created = await createOneShotToken(ttl);
      setRevealed(created);
      setListNonce((nonce) => nonce + 1);
    } catch (caught) {
      setMintError(
        caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="subpanel">
      <h2>One-shot tokens</h2>
      {listAllowed ? (
        <OneShotList key={listNonce} />
      ) : (
        <p className="muted">
          Your account cannot list one-shot tokens (read_service_identities missing) but can
          mint them.
        </p>
      )}
      <form onSubmit={onSubmit} aria-label="Mint a one-shot token">
        <h3>Mint a one-shot token</h3>
        <label>
          TTL (minutes, {ONE_SHOT_TTL_MIN_MINUTES}–{ONE_SHOT_TTL_MAX_MINUTES})
          <input
            type="number"
            min={ONE_SHOT_TTL_MIN_MINUTES}
            max={ONE_SHOT_TTL_MAX_MINUTES}
            step={1}
            value={ttlText}
            onChange={(event) => setTtlText(event.target.value)}
            required
          />
        </label>
        {!ttlValid && (
          <p className="muted" role="note">
            A one-shot token's TTL must be a whole number between{" "}
            {ONE_SHOT_TTL_MIN_MINUTES} minute and {ONE_SHOT_TTL_MAX_MINUTES} minutes (24 hours).
          </p>
        )}
        {mintError && (
          <p className="error-panel" role="alert">
            {mintError.message}
          </p>
        )}
        <button type="submit" disabled={submitting || !ttlValid}>
          {submitting ? "Minting…" : "Mint one-shot token"}
        </button>
      </form>
      {revealed && (
        <TokenReveal
          token={revealed.token}
          caption={`expires ${new Date(revealed.expires_at).toLocaleString()}`}
          onDismiss={() => setRevealed(null)}
          copied={copied}
          onCopied={() => setCopied(true)}
        />
      )}
    </section>
  );
}

function OneShotList() {
  const [rows, setRows] = useState<OneShotToken[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchOneShotTokens({ pageSize: PAGE_SIZE })
      .then((list) => {
        if (!cancelled) setRows(list);
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(
            caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {rows === null && !error && <p className="muted">Loading…</p>}
      {rows !== null && rows.length === 0 && !error && (
        <p className="muted">No one-shot tokens have been minted yet.</p>
      )}
      {rows !== null && rows.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Minted by</th>
              <th>Minted</th>
              <th>Expires</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((token) => (
              <tr key={token.id} className="cert-row">
                <td>
                  <code>{token.minted_by ?? "—"}</code>
                </td>
                <td>{formatDate(token.created_at)}</td>
                <td>{token.expires_at ? formatDate(token.expires_at) : "—"}</td>
                <td>
                  <span
                    className={`status-badge ${token.used_at ? "status-muted" : token.expires_at && new Date(token.expires_at).getTime() < Date.now() ? "status-revoked" : "status-active"}`}
                  >
                    {token.used_at ? "used" : token.expires_at && new Date(token.expires_at).getTime() < Date.now() ? "expired" : "ready"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** The copy-once reveal: the token's only appearance. Copy puts it on
 * the clipboard; Done erases it from the page state for good — nothing
 * renders it again, and leaving the page destroys it anyway. */
function TokenReveal({
  token,
  caption,
  onDismiss,
  copied,
  onCopied,
}: {
  token: string;
  caption: string;
  onDismiss: () => void;
  copied: boolean;
  onCopied: () => void;
}) {
  const codeRef = useRef<HTMLDivElement>(null);
  return (
    <section className="issue-result" aria-label="Minted token">
      <p className="notice" role="status">
        This token is shown to you ONCE. Wardstone never shows it again — copy it now; it is
        gone when you dismiss this notice or leave the page.
      </p>
      <p className="muted">{caption}</p>
      <div className="token-reveal" ref={codeRef}>
        <code>{token}</code>
      </div>
      <div className="detail-actions">
        <button
          type="button"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(token);
            } catch {
              // Clipboard permission refused: the token stays on screen for a manual copy.
            }
            onCopied();
          }}
        >
          {copied ? "Copied." : "Copy token"}
        </button>
        <button type="button" className="danger" onClick={onDismiss}>
          Done — hide it forever
        </button>
      </div>
    </section>
  );
}