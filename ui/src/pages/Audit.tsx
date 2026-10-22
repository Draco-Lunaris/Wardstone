// The audit view: the tenant's log, one paged newest-first page per
// query, through Task 2's filter axes — date range (datetime-local
// inputs, converted to Z-SUFFIX RFC 3339 instants by `rfc3339Z`; the
// `+00:00` encoding trap stays closed at the lib layer) and exact action
// name. Everything sits behind `read_audit`; Apply refuses unconvertible
// input rather than shipping garbage to the wire.

import { useEffect, useState, type FormEvent } from "react";

import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import { AUDIT_PAGE_SIZE, fetchAuditEntries, rfc3339Z, type AuditEntry } from "../lib/audit";
import { hasCapability } from "../lib/certs";

function formatWhen(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** The structured details (ids and labels only — never key material),
 * shown compactly with the full JSON on hover. */
function detailsText(entry: AuditEntry): string {
  if (entry.details === null || entry.details === undefined) {
    return "—";
  }
  const text = JSON.stringify(entry.details);
  return text.length > 80 ? `${text.slice(0, 77)}…` : text;
}

export default function Audit() {
  const auth = useAuthState();

  const [fromInput, setFromInput] = useState("");
  const [toInput, setToInput] = useState("");
  const [actionInput, setActionInput] = useState("");
  // What a click on Apply committed to: from/to ALREADY converted to
  // Z-suffix instants ("" = unfiltered), action trimmed.
  const [applied, setApplied] = useState<{ from: string; to: string; action: string }>({
    from: "",
    to: "",
    action: "",
  });
  const [page, setPage] = useState(0);
  const [rows, setRows] = useState<AuditEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  const fromValue = rfc3339Z(fromInput);
  const toValue = rfc3339Z(toInput);
  // A non-empty input that does not convert blocks Apply (never a
  // mangled instant on the wire).
  const inputsValid =
    (fromInput === "" || fromValue !== null) && (toInput === "" || toValue !== null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchAuditEntries({
      from: applied.from || undefined,
      to: applied.to || undefined,
      action: applied.action || undefined,
      page,
      pageSize: AUDIT_PAGE_SIZE,
    })
      .then((list) => {
        if (!cancelled) {
          setRows(list);
          setError(null);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(
            caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [applied, page]);

  if (!hasCapability(auth.me?.capabilities, "read_audit")) {
    return (
      <main className="page-view">
        <h1>Audit log</h1>
        <p className="muted">
          Your account does not hold the read_audit capability, so it cannot view the audit
          log.
        </p>
      </main>
    );
  }

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!inputsValid) {
      return;
    }
    setApplied({ from: fromValue ?? "", to: toValue ?? "", action: actionInput.trim() });
    setPage(0);
  };

  const resetFilters = () => {
    setFromInput("");
    setToInput("");
    setActionInput("");
    setApplied({ from: "", to: "", action: "" });
    setPage(0);
  };

  return (
    <main className="page-view">
      <div className="page-header">
        <h1>Audit log</h1>
      </div>

      <form className="cert-filters" role="search" aria-label="Audit filters" onSubmit={onSubmit}>
        <label>
          From
          <input
            type="datetime-local"
            step={1}
            aria-label="From"
            value={fromInput}
            onChange={(event) => setFromInput(event.target.value)}
          />
        </label>
        <label>
          To
          <input
            type="datetime-local"
            step={1}
            aria-label="To"
            value={toInput}
            onChange={(event) => setToInput(event.target.value)}
          />
        </label>
        <label>
          Action
          <input
            type="text"
            aria-label="Action"
            placeholder="cert_issued…"
            value={actionInput}
            onChange={(event) => setActionInput(event.target.value)}
          />
        </label>
        <button type="submit" disabled={!inputsValid}>
          Apply
        </button>
        <button type="button" className="secondary" onClick={resetFilters}>
          Reset
        </button>
      </form>
      {!inputsValid && (
        <p className="muted" role="note">
          From/To must be recognizable dates — apply is held until they are.
        </p>
      )}

      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {rows === null && !error && <p className="muted">Loading…</p>}
      {rows !== null && rows.length === 0 && !error && (
        <p className="muted">No audit entries match the current filters.</p>
      )}

      {rows !== null && rows.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>When</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((entry) => (
              <tr key={entry.id} className="cert-row">
                <td>{formatWhen(entry.created_at)}</td>
                <td>
                  <code>{entry.actor_id}</code>
                  <span className="muted"> ({entry.actor_type})</span>
                </td>
                <td>{entry.action}</td>
                <td>
                  {entry.target_type} <code>{entry.target_id}</code>
                </td>
                <td>
                  <code title={JSON.stringify(entry.details)}>{detailsText(entry)}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="page-controls">
        <button
          type="button"
          disabled={page === 0 || loading}
          onClick={() => setPage((current) => Math.max(0, current - 1))}
        >
          Previous
        </button>
        <span className="muted">Page {page + 1}</span>
        <button
          type="button"
          disabled={loading || rows === null || rows.length < AUDIT_PAGE_SIZE}
          onClick={() => setPage((current) => current + 1)}
        >
          Next
        </button>
      </div>
    </main>
  );
}