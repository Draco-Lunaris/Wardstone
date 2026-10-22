//! Shared integration-test fixtures for the ws-web suites: included by a
//! test crate with `mod common;` (a `tests/` directory module — Cargo
//! never builds it standalone, so it stays common code without becoming
//! its own test binary).
//!
//! - [`oidc_provider`] — the loopback OIDC provider stub (Task 19;
//!   deferred here from Task 12 by controller ruling): a full
//!   three-legged provider — discovery, a token endpoint minting a
//!   SIGNATURE-VERIFIABLE id_token, and the matching JWKS — that the e2e
//!   suite drives through ws-api's real OIDC callback.

pub mod oidc_provider;
