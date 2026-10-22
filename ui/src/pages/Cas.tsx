// The certificate-authority view: the tenant's CA list (`read_cas`) with
// per-CA facts every operator of a trust chain needs — the chain to the
// root (downloaded as PEM via the TEXT route), the newest published CRL
// (issued/next-update plus a PEM preview; 404 `not_found` is the honest
// "not published yet"), and the AIA endpoints (OCSP / caIssuers URIs)
// parsed CLIENT-SIDE from the public certificate PEM — fields only, the
// parser lives in lib/certs and never touches key material. The CA key
// export belongs to the admin surfaces, not this day-to-day view.
//
// Rows expand inline (one at a time); the CRL fetch runs on expand so an
// operator paging the list never provokes N CRL requests.

import { Fragment, useEffect, useState } from "react";

import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import {
  downloadText,
  fetchCas,
  fetchCasCrl,
  fetchText,
  hasCapability,
  parseAiaUris,
  type Ca,
  type CrlInfo,
} from "../lib/certs";

/** The accessMethod OIDs the AIA grammar's well-known names map to
 * (1.3.6.1.5.5.7.48.1 OCSP, …48.2 caIssuers); anything else shows its
 * dotted OID verbatim. */
const AIA_METHOD_LABELS: Record<string, string> = {
  "1.3.6.1.5.5.7.48.1": "OCSP",
  "1.3.6.1.5.5.7.48.2": "caIssuers",
};

type CrlState = { kind: "idle" } | { kind: "loading" } | { kind: "none" } | { kind: "error"; error: ApiError } | { kind: "ok"; info: CrlInfo };

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function aiaLabel(method: string): string {
  return AIA_METHOD_LABELS[method] ?? method;
}

export default function Cas() {
  const auth = useAuthState();
  const canManage = hasCapability(auth.me?.capabilities, "manage_cas");
  const canExportKey = hasCapability(auth.me?.capabilities, "export_ca_keys");

  const [cas, setCas] = useState<Ca[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [crlStates, setCrlStates] = useState<Record<string, CrlState>>({});
  const [chainBusyId, setChainBusyId] = useState<string | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchCas()
      .then((rows) => {
        if (!cancelled) setCas(rows);
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0));
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const parentNameOf = (id: string | null): string | null => {
    if (!id) {
      return null;
    }
    return cas?.find((ca) => ca.id === id)?.name ?? null;
  };

  // Expanding a row lazily pulls that CA's CRL (or its 404, which is the
  // "nothing published" state).
  const expand = (id: string) => {
    const next = expandedId === id ? null : id;
    setExpandedId(next);
    setChainError(null);
    if (next && !crlStates[next]) {
      setCrlStates((states) => ({ ...states, [next]: { kind: "loading" } }));
      let cancelled = false;
      fetchCasCrl(next)
        .then((info) => {
          if (!cancelled) {
            setCrlStates((states) => ({
              ...states,
              [next]: info ? { kind: "ok", info } : { kind: "none" },
            }));
          }
        })
        .catch((caught) => {
          if (!cancelled) {
            setCrlStates((states) => ({
              ...states,
              [next]: {
                kind: "error",
                error:
                  caught instanceof ApiError
                    ? caught
                    : new ApiError("transport", String(caught), 0),
              },
            }));
          }
        });
    }
  };

  const downloadChain = async (ca: Ca) => {
    setChainBusyId(ca.id);
    setChainError(null);
    try {
      const pem = await fetchText(`/api/v1/cas/${encodeURIComponent(ca.id)}/chain`);
      downloadText(pem, "application/x-pem-file", `wardstone-ca-${ca.name}-chain.pem`);
    } catch (caught) {
      setChainError(
        caught instanceof ApiError ? caught.message : String(caught),
      );
    } finally {
      setChainBusyId(null);
    }
  };

  if (!hasCapability(auth.me?.capabilities, "read_cas")) {
    return (
      <main className="page-view">
        <h1>Certificate authorities</h1>
        <p className="muted">
          Your account does not hold the read_cas capability, so it cannot view the trust
          chain.
        </p>
      </main>
    );
  }

  return (
    <main className="page-view">
      <div className="page-header">
        <h1>Certificate authorities</h1>
      </div>

      {canManage && (
        <p className="muted">
          CA creation and key export run through the API (capabilities manage_cas and
          export_ca_keys).
        </p>
      )}

      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {cas === null && !error && <p className="muted">Loading…</p>}
      {cas !== null && cas.length === 0 && !error && (
        <p className="muted">No certificate authorities exist yet.</p>
      )}

      {cas !== null && cas.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Subject</th>
              <th>Kind</th>
              <th>Key type</th>
              <th>Expires</th>
              <th aria-label="Details" />
            </tr>
          </thead>
          <tbody>
            {cas.map((ca) => (
              <Fragment key={ca.id}>
                <tr className="cert-row">
                  <td>{ca.name}</td>
                  <td>{ca.subject}</td>
                  <td>
                    <span className="status-badge status-active">
                      {ca.is_root ? "root" : "intermediate"}
                    </span>
                  </td>
                  <td>{ca.key_type}</td>
                  <td>{formatDate(ca.not_after)}</td>
                  <td>
                    <button
                      type="button"
                      className="secondary"
                      aria-expanded={expandedId === ca.id}
                      onClick={() => expand(ca.id)}
                    >
                      {expandedId === ca.id ? "Hide details" : "Details"}
                    </button>
                  </td>
                </tr>
                {expandedId === ca.id && (
                  <tr>
                    <td colSpan={6} className="ca-detail-cell">
                      <CaDetails
                        ca={ca}
                        parentName={parentNameOf(ca.parent_id)}
                        crlState={crlStates[ca.id] ?? { kind: "idle" }}
                        onToggleCrl={() => expand(ca.id)}
                        onDownloadChain={() => downloadChain(ca)}
                        chainBusy={chainBusyId === ca.id}
                        chainError={chainError}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
      {canExportKey && (
        <p className="muted">
          CA key export (capability export_ca_keys) is deliberately absent from this view: it
          belongs to the admin surfaces.
        </p>
      )}
    </main>
  );
}

function CaDetails({
  ca,
  parentName,
  crlState,
  onToggleCrl,
  onDownloadChain,
  chainBusy,
  chainError,
}: {
  ca: Ca;
  parentName: string | null;
  crlState: CrlState;
  onToggleCrl: () => void;
  onDownloadChain: () => void;
  chainBusy: boolean;
  chainError: string | null;
}) {
  const aia = parseAiaUris(ca.cert_pem);
  return (
    <div className="subpanel">
      <dl className="detail-grid">
        <dt>Subject</dt>
        <dd>{ca.subject}</dd>
        <dt>Parent</dt>
        <dd>{ca.is_root ? "— (trust anchor)" : (parentName ?? ca.parent_id)}</dd>
        <dt>Valid from</dt>
        <dd>{formatDate(ca.not_before)}</dd>
        <dt>Valid until</dt>
        <dd>{formatDate(ca.not_after)}</dd>
        <dt>Created</dt>
        <dd>{formatDate(ca.created_at)}</dd>
      </dl>

      <h3>Authority information access</h3>
      {aia.length === 0 ? (
        <p className="muted">
          No AIA extension on this CA certificate (use the PEM download and your own tooling
          for anything beyond these fields).
        </p>
      ) : (
        <ul className="aia-list">
          {aia.map((entry) => (
            <li key={`${entry.method}:${entry.uri}`}>
              <span className="san-kind">{aiaLabel(entry.method)}</span>{" "}
              <code>{entry.uri}</code>
            </li>
          ))}
        </ul>
      )}

      <div className="detail-actions">
        <button
          type="button"
          onClick={() =>
            downloadText(ca.cert_pem, "application/x-pem-file", `wardstone-ca-${ca.name}.pem`)
          }
        >
          Download certificate (PEM)
        </button>
        <button type="button" disabled={chainBusy} onClick={onDownloadChain}>
          {chainBusy ? "Downloading…" : "Download chain (PEM)"}
        </button>
        <button type="button" onClick={onToggleCrl}>
          Hide details
        </button>
      </div>
      {chainError && (
        <p className="error-panel" role="alert">
          {chainError}
        </p>
      )}

      <h3>Latest CRL</h3>
      {crlState.kind === "loading" && <p className="muted">Loading CRL…</p>}
      {crlState.kind === "none" && (
        <p className="muted">No CRL has been published for this CA yet.</p>
      )}
      {crlState.kind === "error" && (
        <p className="error-panel" role="alert">
          {crlState.error.message}
        </p>
      )}
      {crlState.kind === "ok" && (
        <dl className="detail-grid">
          <dt>Issued</dt>
          <dd>{new Date(crlState.info.issued_at).toLocaleString()}</dd>
          <dt>Next update</dt>
          <dd>{new Date(crlState.info.next_update).toLocaleString()}</dd>
        </dl>
      )}
      {crlState.kind === "ok" && (
        <>
          <label htmlFor={`crl-preview-${ca.id}`}>CRL PEM</label>
          <textarea
            id={`crl-preview-${ca.id}`}
            className="mono"
            rows={6}
            readOnly
            value={crlState.info.crl_pem}
          />
          <div className="detail-actions">
            <button
              type="button"
              onClick={() =>
                downloadText(
                  crlState.info.crl_pem,
                  "application/pkix-crl",
                  `wardstone-ca-${ca.name}.crl.pem`,
                )
              }
            >
              Download CRL (PEM)
            </button>
          </div>
        </>
      )}
    </div>
  );
}