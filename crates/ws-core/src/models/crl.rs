//! The published-CRL domain model (`crls` rows).

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One published certificate revocation list for a CA: the `crls` row the
/// ws-worker's CRL job writes. The table is worker-owned (no other writer
/// exists); this model is its first read-side shape. `tenant_id` is the
/// denormalized copy of the CA's tenant (migration 006's composite foreign
/// key keeps it honest) and is what the queries filter on.
#[derive(Debug, Clone, PartialEq)]
pub struct CrlEntry {
    /// The CA the CRL is published for.
    pub ca_id: Uuid,
    /// Owning tenant (the CA's tenant).
    pub tenant_id: Uuid,
    /// When the CRL was issued.
    pub issued_at: DateTime<Utc>,
    /// When the next CRL is due (the `thisUpdate` of the next edition).
    pub next_update: DateTime<Utc>,
    /// PEM-encoded X.509 CRL document.
    pub crl_pem: String,
}
