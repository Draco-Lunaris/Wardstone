// The ACME operator page (Plan 4 Task 10): the /api/v1/acme REST
// projection's accounts table (status badges, the precomputed
// orders_count), the per-account orders sub-table (lifecycle status,
// identifiers, profile, the issued certificate's link), the deactivation
// dialog — a one-way gate whose cascade (pending authorizations
// invalidated, open orders invalid) is spelled OUT LOUD before the
// confirm — and the deep link from a certificate's detail
// (`/acme?certificate=<id>` resolves the order the certificate came
// from).
//
// Capability discipline (the nav's gates mirror it): without `read_acme`
// the page says so and fetches nothing; the deactivate affordance renders
// only behind `manage_acme_accounts` — gate the affordance, don't provoke
// a 403. The JWS machine surface (`/acme/{tenant}/…`) is never touched
// from here; this page speaks ordinary REST only.

import { Fragment, useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import {
  deactivateAcmeAccount,
  fetchAcmeAccounts,
  fetchAcmeOrders,
  identifierValues,
  type AcmeAccount,
  type AcmeOrder,
} from "../lib/acme";
import { hasCapability } from "../lib/certs";

const PAGE_SIZE = 25;

/** The stored account-status vocabulary mapped onto the house badge
 * classes: the usable state is accented, the refused one alarmed, and
 * everything unremarkable is muted. */
const ACCOUNT_BADGE: Record<string, string> = {
  valid: "status-active",
  deactivated: "status-revoked",
  pending: "status-muted",
};

/** The order-status badges: `valid` is the terminal-good state; `invalid`
 * is the failure; the three in-flight states stay muted. */
const ORDER_BADGE: Record<string, string> = {
  pending: "status-muted",
  ready: "status-muted",
  processing: "status-muted",
  valid: "status-active",
  invalid: "status-revoked",
};

function badgeClass(status: string, map: Record<string, string>): string {
  return `status-badge ${map[status] ?? "status-muted"}`;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/** One account's expanded orders pane's data (never rendered for another
 * account — the accountId guard is checked at render time). */
interface OrdersPane {
  accountId: string;
  orders: AcmeOrder[];
}

export default function Acme() {
  const auth = useAuthState();
  const canRead = hasCapability(auth.me?.capabilities, "read_acme");
  const canManage = hasCapability(auth.me?.capabilities, "manage_acme_accounts");

  const [searchParams] = useSearchParams();
  const certificateId = searchParams.get("certificate");

  const [accounts, setAccounts] = useState<AcmeAccount[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  // Bumped after a deactivate succeeds: the list re-fetches and the row
  // shows the deactivated state.
  const [reload, setReload] = useState(0);
  const [page, setPage] = useState(0);

  const [expanded, setExpanded] = useState<string | null>(null);
  const [orders, setOrders] = useState<OrdersPane | null>(null);
  const [ordersLoading, setOrdersLoading] = useState(false);
  const [ordersError, setOrdersError] = useState<ApiError | null>(null);

  const [deactivating, setDeactivating] = useState<AcmeAccount | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [dialogError, setDialogError] = useState<ApiError | null>(null);

  // The certificate deep link's outcome: a muted notice (success or the
  // ordinary no-order state) or the failure panel.
  const [notice, setNotice] = useState<string | null>(null);
  const [noticeError, setNoticeError] = useState<ApiError | null>(null);

  useEffect(() => {
    if (!canRead) {
      return;
    }
    let cancelled = false;
    setLoading(true);
    fetchAcmeAccounts({ page, pageSize: PAGE_SIZE })
      .then((list) => {
        if (!cancelled) {
          setAccounts(list);
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
  }, [canRead, page, reload]);

  // The deep link: resolve the certificate's order once, pre-seed its
  // account's orders pane (the account_id fetch it would trigger is this
  // same list), and expand that account. A certificate without an order
  // (manually issued, or an id that outlived its row) is an ordinary
  // state, not an error.
  useEffect(() => {
    if (!certificateId || !canRead) {
      return;
    }
    let cancelled = false;
    setNotice(null);
    setNoticeError(null);
    fetchAcmeOrders({ certificateId })
      .then((list) => {
        if (cancelled) {
          return;
        }
        if (list.length === 0) {
          setNotice(`No ACME order was found for certificate ${certificateId}.`);
          return;
        }
        setOrders({ accountId: list[0].account_id, orders: list });
        setExpanded(list[0].account_id);
        setNotice(`Showing the ACME order that issued certificate ${certificateId}.`);
      })
      .catch((caught) => {
        if (!cancelled) {
          setNoticeError(
            caught instanceof ApiError
              ? caught
              : new ApiError("transport", String(caught), 0),
          );
        }
      });
    return () => {
      cancelled = true;
    };
    // The certificate id is the page-mount parameter; it is not expected
    // to change while mounted.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [certificateId, canRead]);

  const loadOrders = (accountId: string, preloaded?: AcmeOrder[]) => {
    setOrdersLoading(true);
    setOrdersError(null);
    if (preloaded) {
      setOrders({ accountId, orders: preloaded });
      setOrdersLoading(false);
      return;
    }
    fetchAcmeOrders({ accountId })
      .then((list) => {
        setOrders({ accountId, orders: list });
      })
      .catch((caught) => {
        setOrdersError(
          caught instanceof ApiError
            ? caught
            : new ApiError("transport", String(caught), 0),
        );
      })
      .finally(() => {
        setOrdersLoading(false);
      });
  };

  const toggleOrders = (account: AcmeAccount) => {
    if (expanded === account.id) {
      setExpanded(null);
      setOrders(null);
      setOrdersError(null);
      return;
    }
    setExpanded(account.id);
    // A deep link may have already seeded this account's pane; a re-fetch
    // would only race it.
    if (orders?.accountId !== account.id) {
      loadOrders(account.id);
    }
  };

  const handleDeactivate = async (event: FormEvent) => {
    event.preventDefault();
    if (!deactivating || submitting) {
      return;
    }
    setSubmitting(true);
    setDialogError(null);
    try {
      await deactivateAcmeAccount(deactivating.id);
      setDeactivating(null);
      setReload((current) => current + 1);
    } catch (caught) {
      setDialogError(
        caught instanceof ApiError
          ? caught
          : new ApiError("transport", String(caught), 0),
      );
    } finally {
      setSubmitting(false);
    }
  };

  if (!canRead) {
    return (
      <main className="page-view">
        <div className="page-header">
          <h1>ACME</h1>
        </div>
        <p className="error-panel" role="alert">
          The ACME view requires the read_acme capability; ask an
          administrator if you believe you should hold it.
        </p>
      </main>
    );
  }

  return (
    <main className="page-view">
      <div className="page-header">
        <h1>ACME</h1>
      </div>

      {notice && <p className="muted">{notice}</p>}
      {noticeError && (
        <p className="error-panel" role="alert">
          {noticeError.message}
        </p>
      )}

      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {accounts === null && !error && <p className="muted">Loading…</p>}
      {accounts !== null && accounts.length === 0 && !error && (
        <p className="muted">
          No ACME clients have enrolled yet. Enrolment happens through the
          RFC 8555 machine surface with an ACME client, not through this
          page.
        </p>
      )}

      {accounts !== null && accounts.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Key thumbprint</th>
              <th>Contact</th>
              <th>Status</th>
              <th>Orders</th>
              <th>Created</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {accounts.map((account) => (
              <Fragment key={account.id}>
                <tr>
                  <td>
                    <code>{account.jwk_thumbprint}</code>
                  </td>
                  <td>{account.contact ?? "—"}</td>
                  <td>
                    <span className={badgeClass(account.status, ACCOUNT_BADGE)}>
                      {account.status}
                    </span>
                  </td>
                  <td>{account.orders_count}</td>
                  <td>{formatDate(account.created_at)}</td>
                  <td>
                    <button
                      type="button"
                      aria-expanded={expanded === account.id}
                      aria-label={`Orders of ${account.jwk_thumbprint}`}
                      onClick={() => toggleOrders(account)}
                    >
                      Orders
                    </button>
                    {canManage && (
                      <button
                        type="button"
                        className="danger"
                        onClick={() => {
                          setDeactivating(account);
                          setDialogError(null);
                        }}
                      >
                        Deactivate…
                      </button>
                    )}
                  </td>
                </tr>
                {expanded === account.id && (
                  <tr>
                    <td colSpan={6}>
                      {ordersLoading && <p className="muted">Loading orders…</p>}
                      {ordersError && (
                        <p className="error-panel" role="alert">
                          {ordersError.message}
                        </p>
                      )}
                      {orders?.accountId === account.id &&
                        orders.orders.length === 0 &&
                        !ordersLoading && (
                          <p className="muted">This account has not placed any orders.</p>
                        )}
                      {orders?.accountId === account.id &&
                        orders.orders.length > 0 &&
                        !ordersLoading && (
                          <table className="cert-table">
                            <thead>
                              <tr>
                                <th>Status</th>
                                <th>Identifiers</th>
                                <th>Profile</th>
                                <th>Certificate</th>
                                <th>Expires</th>
                                <th>Error</th>
                              </tr>
                            </thead>
                            <tbody>
                              {orders.orders.map((order: AcmeOrder) => (
                                <tr key={order.id}>
                                  <td>
                                    <span className={badgeClass(order.status, ORDER_BADGE)}>
                                      {order.status}
                                    </span>
                                  </td>
                                  <td>{identifierValues(order).join(", ") || "—"}</td>
                                  <td>{order.profile_name}</td>
                                  <td>
                                    {order.certificate_id ? (
                                      <Link to={`/certificates/${order.certificate_id}`}>
                                        View certificate
                                      </Link>
                                    ) : (
                                      "—"
                                    )}
                                  </td>
                                  <td>{formatDate(order.expires_at)}</td>
                                  <td>{order.error ?? "—"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}
                    </td>
                  </tr>
                )}
              </Fragment>
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
          disabled={loading || accounts === null || accounts.length < PAGE_SIZE}
          onClick={() => setPage((current) => current + 1)}
        >
          Next
        </button>
      </div>

      {deactivating && (
        <div className="dialog-overlay">
          <div
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="acme-deactivate-title"
          >
            <h2 id="acme-deactivate-title">Deactivate ACME account</h2>
            <p className="dialog-subject">
              {deactivating.contact ?? deactivating.jwk_thumbprint}
            </p>

            <p>
              Deactivation is one-way: every pending authorization of this
              account is invalidated and every open order is marked invalid.
              The client loses access until it re-enrolls with a fresh key.
            </p>

            {dialogError && (
              <p className="error-panel" role="alert">
                {dialogError.message}
              </p>
            )}

            <form onSubmit={handleDeactivate}>
              <div className="dialog-actions">
                <button
                  type="button"
                  onClick={() => setDeactivating(null)}
                  disabled={submitting}
                >
                  Cancel
                </button>
                <button type="submit" className="danger" disabled={submitting}>
                  {submitting ? "Deactivating…" : "Deactivate account"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </main>
  );
}