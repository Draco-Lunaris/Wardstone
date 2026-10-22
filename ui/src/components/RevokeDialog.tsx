// The revoke dialog: the typed-reason dropdown (the nine RFC 5280 names
// — the exact spellings ws-worker parses into CRL/OCSP extensions) plus
// an optional free-text detail. The server is idempotent, so a revoke of
// an already-revoked certificate just re-lands in the detail view;
// failures surface ws-api's message VERBATIM (e.g. `bad_request`'s
// "not permitted by profile" phrasing).
//
// The OPENING of this dialog is the caller's capability gate — a caller
// without `issue` never renders it.

import { useState, type FormEvent } from "react";

import {
  REVOCATION_REASONS,
  revokeCertificate,
  type Certificate,
  type RevocationReason,
  type RevokeResponse,
} from "../lib/certs";
import { ApiError } from "../lib/api";

/** The human labels for the nine typed reasons (the wire values stay the
 * snake_case names). */
const REASON_LABELS: Record<RevocationReason, string> = {
  unspecified: "Unspecified (RFC 5280)",
  key_compromise: "Key compromise",
  ca_compromise: "CA compromise",
  affiliation_changed: "Affiliation changed",
  superseded: "Superseded",
  cessation_of_operation: "Cessation of operation",
  certificate_hold: "Certificate hold",
  privilege_withdrawn: "Privilege withdrawn",
  aa_compromise: "AA compromise",
};

interface RevokeDialogProps {
  certificate: Certificate;
  onClose: () => void;
  /** Called with the route's response on success (first revoke or the
   * idempotent no-op alike) before onClose. */
  onRevoked?: (response: RevokeResponse) => void;
}

export default function RevokeDialog({ certificate, onClose, onRevoked }: RevokeDialogProps) {
  const [reason, setReason] = useState<RevocationReason>("unspecified");
  const [detail, setDetail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (submitting) {
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const response = await revokeCertificate(certificate.id, reason, detail);
      onRevoked?.(response);
      onClose();
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught
          : new ApiError(
              "transport",
              caught instanceof Error ? caught.message : "the revocation could not be sent",
              0,
            ),
      );
      setSubmitting(false);
    }
  };

  return (
    <div className="dialog-overlay">
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="revoke-title"
      >
        <h2 id="revoke-title">Revoke certificate</h2>
        <p className="dialog-subject">
          {certificate.subject} · {certificate.serial_hex}
        </p>

        {error && (
          <p className="error-panel" role="alert">
            {error.message}
          </p>
        )}

        <form onSubmit={onSubmit}>
          <label htmlFor="revoke-reason">Reason</label>
          <select
            id="revoke-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value as RevocationReason)}
          >
            {REVOCATION_REASONS.map((value) => (
              <option key={value} value={value}>
                {REASON_LABELS[value]}
              </option>
            ))}
          </select>

          <label htmlFor="revoke-detail">Detail (optional)</label>
          <textarea
            id="revoke-detail"
            rows={3}
            value={detail}
            onChange={(event) => setDetail(event.target.value)}
            placeholder="e.g. the laptop holding this key was stolen"
          />

          <div className="dialog-actions">
            <button type="button" onClick={onClose} disabled={submitting}>
              Cancel
            </button>
            <button type="submit" className="danger" disabled={submitting}>
              {submitting ? "Revoking…" : "Revoke certificate"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}