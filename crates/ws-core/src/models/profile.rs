//! The certificate-profile domain models (`profiles` and
//! `profile_revisions` rows) and the built-in default profiles.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::models::rbac::KeyUsagePurpose;

/// One row of `profiles`: a named CA-profile family of one tenant whose
/// current policy is [`ProfileModel::current_revision_id`].
///
/// The circular reference with [`ProfileRevisionModel`] is cut in the
/// schema: a fresh profile starts with a `current_revision_id` of `None`
/// and the (deferrable) FK only requires the pointer to resolve once a
/// first revision exists. Repositories append revisions and repoint with
/// an optimistic-concurrency compare-and-swap.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileModel {
    /// Primary key (chosen by the caller).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// Profile name, unique per tenant.
    pub name: String,
    /// Free-form description.
    pub description: Option<String>,
    /// The revision the profile currently points at; `None` until the
    /// first revision exists.
    pub current_revision_id: Option<Uuid>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
}

/// One row of `profile_revisions`: one immutable published version of a
/// profile. A revision never changes once certificates reference it.
///
/// The SAN pattern list is validated by `ws_core::profile_match`; the key
/// usages and EKUs are TEXT arrays of the shared vocabularies
/// ([`KeyUsagePurpose`] spellings and RFC 5280 EKU names).
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileRevisionModel {
    /// Primary key (chosen by the caller).
    pub id: Uuid,
    /// Owning profile (`profiles.id`, insert-time FK).
    pub profile_id: Uuid,
    /// Monotonic revision number, unique per profile
    /// (`UNIQUE (profile_id, revision)`).
    pub revision: i32,
    /// The revision's own name (its label on the profile family).
    pub name: String,
    /// Key algorithm as stored text (`rsa2048`, `ecdsa-p256`, ...).
    pub key_type: String,
    /// Key usages as [`KeyUsagePurpose::as_str`] spellings (the
    /// `key_usages TEXT[]` column; the single vocabulary of the
    /// workspace — no RFC camelCase aliases).
    pub key_usages: Vec<String>,
    /// Extended key usages as RFC 5280 names (`server_auth`, ...).
    pub eku: Vec<String>,
    /// Certificate lifetime in days.
    pub lifetime_days: i32,
    /// SAN patterns matched by `ws_core::profile_match::san_is_permitted`.
    pub san_patterns: Vec<String>,
    /// True for the migration-008 legacy backfill rows, which were never
    /// used for issuance and are display-only.
    pub is_legacy: bool,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Who created the revision (free text; the migration backfill uses
    /// `system:migration-008`).
    pub actor_id: String,
}

impl ProfileRevisionModel {
    /// A template of `self` for the caller to persist as the NEXT
    /// revision of `profile_id`, with the caller's chosen fields
    /// overwritten: new `revision` number, new `id`, fresh `created_at`.
    ///
    /// `default_profiles` seeds its built-ins with this so the built-ins
    /// stay a plain data source without minting UUIDs of their own.
    #[must_use]
    pub fn template_for(&self, profile_id: Uuid, revision: i32, id: Uuid) -> Self {
        ProfileRevisionModel {
            id,
            profile_id,
            revision,
            created_at: Utc::now(),
            ..self.clone()
        }
    }
}

/// The built-in default profiles for a fresh setup, as revision
/// templates keyed to the calling id/revision scheme (see
/// [`ProfileRevisionModel::template_for`]).
///
/// Exactly two built-ins exist:
///
/// - `web-server`: `rsa2048` keys,
///   `digital_signature` + `key_encipherment`, EKU `server_auth`,
///   30-day lifetime;
/// - `web-server-ecdsa`: `ecdsa-p256` keys, `digital_signature`,
///   EKU `server_auth`, 30-day lifetime.
///
/// Both carry the SAN pattern list `[domain, *.domain, ...cidrs]`, and
/// both MUST carry key usages (an empty list is illegal — a profile
/// without key usages could issue nothing).
///
/// The models are returned with `id: Uuid::nil()` and `profile_id:
/// Uuid::nil()`: the caller fills both (plus the revision number) when
/// persisting, via [`ProfileRevisionModel::template_for`].
#[must_use]
pub fn default_profiles(domain: &str, domain_cidrs: &[String]) -> Vec<ProfileRevisionModel> {
    let mut san_patterns = vec![domain.to_string(), format!("*.{domain}")];
    san_patterns.extend(domain_cidrs.iter().cloned());

    let web_server_rsa = ProfileRevisionModel {
        id: Uuid::nil(),
        profile_id: Uuid::nil(),
        revision: 1,
        name: "web-server".to_string(),
        key_type: "rsa2048".to_string(),
        key_usages: vec![
            KeyUsagePurpose::DigitalSignature.as_str().to_string(),
            KeyUsagePurpose::KeyEncipherment.as_str().to_string(),
        ],
        eku: vec!["server_auth".to_string()],
        lifetime_days: 30,
        san_patterns,
        is_legacy: false,
        created_at: Utc::now(),
        actor_id: "system".to_string(),
    };

    let web_server_ecdsa = ProfileRevisionModel {
        name: "web-server-ecdsa".to_string(),
        key_type: "ecdsa-p256".to_string(),
        key_usages: vec![KeyUsagePurpose::DigitalSignature.as_str().to_string()],
        ..web_server_rsa.clone()
    };

    vec![web_server_rsa, web_server_ecdsa]
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::default_profiles;

    /// The two built-ins carry the pinned key usages, EKU, lifetime, and
    /// SAN patterns; the caller fills ids/revision.
    #[test]
    fn default_profiles_carry_the_pinned_policy() {
        let profiles = default_profiles("example.test", &["10.0.0.0/8".to_string()]);
        assert_eq!(profiles.len(), 2);

        let rsa = &profiles[0];
        assert_eq!(rsa.name, "web-server");
        assert_eq!(rsa.key_type, "rsa2048");
        assert_eq!(
            rsa.key_usages,
            vec![
                "digital_signature".to_string(),
                "key_encipherment".to_string()
            ]
        );
        assert_eq!(rsa.eku, vec!["server_auth".to_string()]);
        assert_eq!(rsa.lifetime_days, 30);
        assert!(!rsa.is_legacy);

        let ecdsa = &profiles[1];
        assert_eq!(ecdsa.name, "web-server-ecdsa");
        assert_eq!(ecdsa.key_type, "ecdsa-p256");
        assert_eq!(ecdsa.key_usages, vec!["digital_signature".to_string()]);
        assert_eq!(ecdsa.eku, vec!["server_auth".to_string()]);
        assert_eq!(ecdsa.lifetime_days, 30);

        for p in &profiles {
            assert_eq!(
                p.san_patterns,
                vec![
                    "example.test".to_string(),
                    "*.example.test".to_string(),
                    "10.0.0.0/8".to_string(),
                ]
            );
        }
    }
}
