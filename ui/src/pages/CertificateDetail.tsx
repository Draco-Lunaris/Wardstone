// The certificate detail: the fields grid (subject, SANs including IPs,
// serial hex, validity window, key type, status, the revocation pair),
// the PEM downloads (the certificate's own PEM from the detail body; the
// chain route's x-pem-file TEXT fetched and wrapped in a blob), and the
// revoke affordance gated on the `issue` capability — a viewer without
// it never sees the button, matching the server's capability check.

import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import RevokeDialog from "../components/RevokeDialog";
import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import {
  downloadText,
  fetchCertificate,
  fetchText,
  hasCapability,
  type Certificate,
} from "../lib/certs";

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

export default function CertificateDetail() {
  const { id } = useParams<{ id: string }>();
  const auth = useAuthState();
  const canRevoke = hasCapability(auth.me?.capabilities, "issue");

  const [cert, setCert] = useState<Certificate | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  // Bumped after a revoke succeeds: the effect re-fetches and the page
  // shows the revoked state (the route is idempotent, so a repeat simply
  // re-answers with the first revoke's stored pair).
  const [reload, setReload] = useState(0);

  const [revoking, setRevoking] = useState(false);
  const [downloadingChain, setDownloadingChain] = useState(false);
  const [downloadError, setDownloadError] = useState<ApiError | null>(null);

  useEffect(() => {
    if (!id) {
      return;
    }
    let cancelled = false;
    setLoading(true);
    fetchCertificate(id)
      .then((value) => {
        if (!cancelled) {
          setCert(value);
          setError(null);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(
            caught instanceof ApiError
              ? caught
              : new ApiError("transport", String(caught), 0),
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [id, reload]);

  const downloadChain = async () => {
    if (!id || downloadingChain) {
      return;
    }
    setDownloadingChain(true);
    setDownloadError(null);
    try {
      const pem = await fetchText(
        `/api/v1/certificates/${encodeURIComponent(id)}/chain`,
      );
      downloadText(
        pem,
        "application/x-pem-file",
        `wardstone-chain-${cert?.serial_hex ?? id}.pem`,
      );
    } catch (caught) {
      setDownloadError(
        caught instanceof ApiError
          ? caught
          : new ApiError("transport", String(caught), 0),
      );
    } finally {
      setDownloadingChain(false);
    }
  };

  return (
    <main className="page-view">
      <div className="page-header">
        <h1>Certificate</h1>
        {cert && <span className={`status-badge status-${cert.status}`}>{cert.status}</span>}
      </div>

      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {loading && !cert && !error && <p className="muted">Loading…</p>}

      {cert && (
        <>
          <dl className="detail-grid">
            <dt>Subject</dt>
            <dd>{cert.subject}</dd>
            <dt>Serial (hex)</dt>
            <dd>
              <code>{cert.serial_hex}</code>
            </dd>
            <dt>Profile</dt>
            <dd>{cert.profile_name}</dd>
            <dt>Key type</dt>
            <dd>{cert.key_type}</dd>
            <dt>Valid from</dt>
            <dd>{formatDateTime(cert.not_before)}</dd>
            <dt>Expires</dt>
            <dd>{formatDateTime(cert.not_after)}</dd>
            <dt>Source</dt>
            <dd>{cert.source}</dd>
            <dt>Issued</dt>
            <dd>{formatDateTime(cert.created_at)}</dd>
          </dl>

          {(cert.san_dns.length > 0 || cert.san_ips.length > 0) && (
            <section>
              <h2>Subject alternative names</h2>
              <ul className="san-list">
                {cert.san_dns.map((name) => (
                  <li key={name}>{name}</li>
                ))}
                {cert.san_ips.map((ip) => (
                  <li key={ip}>
                    {ip} <span className="san-kind">(IP)</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {cert.status === "revoked" && (
            <section className="revoked-block">
              <h2>Revocation</h2>
              <dl className="detail-grid">
                <dt>Revoked at</dt>
                <dd>{cert.revoked_at ? formatDateTime(cert.revoked_at) : "—"}</dd>
                <dt>Reason</dt>
                <dd>{cert.revocation_reason ?? "—"}</dd>
                <dt>Detail</dt>
                <dd>{cert.revocation_detail ?? "—"}</dd>
              </dl>
            </section>
          )}

          <div className="detail-actions">
            <button
              type="button"
              onClick={() =>
                downloadText(
                  cert.cert_pem,
                  "application/x-pem-file",
                  `wardstone-cert-${cert.serial_hex}.pem`,
                )
              }
            >
              Download certificate PEM
            </button>
            <button type="button" onClick={downloadChain} disabled={downloadingChain}>
              {downloadingChain ? "Preparing…" : "Download chain (PEM)"}
            </button>
            {canRevoke && (
              <button type="button" className="danger" onClick={() => setRevoking(true)}>
                Revoke…
              </button>
            )}
          </div>

          <p className="back-link">
            <Link to="/certificates">← All certificates</Link>
          </p>
        </>
      )}

      {downloadError && (
        <p className="error-panel" role="alert">
          {downloadError.message}
        </p>
      )}

      {revoking && cert && (
        <RevokeDialog
          certificate={cert}
          onClose={() => setRevoking(false)}
          onRevoked={() => setReload((current) => current + 1)}
        />
      )}
    </main>
  );
}