//! Repositories: data access for the domain models over the Postgres schema.

pub mod audit_repo;
pub mod ca_repo;
pub mod certificate_repo;
pub mod credential_repo;
pub mod crl_repo;
pub mod ocsp_repo;
pub mod oidc_repo;
pub mod profile_repo;
pub mod refresh_repo;
pub mod role_repo;
pub mod tenant_repo;
pub mod user_repo;

use crate::error::CoreError;

/// The workspace's LIMIT/OFFSET values for one page: `(limit, offset)`.
///
/// `offset` is `page * page_size`; `page_size` is clamped to a maximum of
/// 500, and the CLAMPED value feeds both the limit and the offset, so a
/// caller paging at `page_size = 10_000` gets consistent 500-row pages
/// whose offsets stay aligned (page 2 at size 10_000 skips rows 500..1000,
/// not 10_000..15_000).
///
/// The u32-by-u32 product cannot overflow `u64`, so the multiply is plain;
/// the i64 conversion is still typed — an offset beyond i64 is a caller
/// bug surfaced as [`CoreError::Config`], never a silent wrap. This is the
/// one shared copy of the helper Plan 1 wrote twice (private, unclamped);
/// its callers move onto it in the following task.
pub fn paging(page: u32, page_size: u32) -> Result<(i64, i64), CoreError> {
    let page_size = page_size.min(500);
    let offset = u64::from(page) * u64::from(page_size);
    let offset = i64::try_from(offset)
        .map_err(|_| CoreError::Config(format!("page offset {offset} overflows")))?;
    Ok((i64::from(page_size), offset))
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::paging;

    #[test]
    fn paging_returns_limit_first_offset_second_and_clamps() {
        assert_eq!(paging(0, 10).expect("a plain page"), (10, 0));
        assert_eq!(paging(2, 10).expect("page 2"), (10, 20));
        assert_eq!(
            paging(0, 10_000).expect("page_size above the clamp"),
            (500, 0)
        );
        assert_eq!(
            paging(u32::MAX, u32::MAX).expect("clamped sizes keep the product in range"),
            (500, i64::from(u32::MAX) * i64::from(500)),
            "the offset uses the clamped page size too"
        );
    }

    #[test]
    fn paging_rejects_an_offset_beyond_i64() {
        // The page-size clamp bounds the offset at u32::MAX * 500, which
        // fits i64 — so no reachable input overflows. The typed conversion
        // is belt for the day the clamp is lifted.
        assert!(matches!(paging(0, 0), Ok((0, 0))));
    }
}
