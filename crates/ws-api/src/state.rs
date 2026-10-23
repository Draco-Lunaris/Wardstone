//! The application state of the REST surface: the pool, the JWT key pair,
//! the deployment config (including the ACME URL base), the bounded access
//! log, the OIDC csrf-state store, and the ACME nonce ledger.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use ws_acme::NonceStore;
use ws_auth::jwt::JwtKeys;

use crate::routes::acme::{
    ChallengeFetch, FailingFetcher, FailingTxtResolver, Http01Fetcher, TxtResolver,
    TxtResolverHandle,
};

/// The name of the TOTP/OIDC secret-encryption key file inside the keys
/// directory (`ws_core::crypto::SecretBox`'s envelope key, created at
/// setup under the keys volume).
pub const SECRET_KEY_FILE: &str = "secret-encryption.key";

/// The issuer name the TOTP provisioning URIs carry.
pub const TOTP_ISSUER: &str = "Wardstone";

/// How long a minted OIDC csrf state stays valid in the store.
const OIDC_STATE_TTL: Duration = Duration::from_secs(10 * 60);

/// The deployment configuration the setup flow established. Carried (and
/// kept immutable) in the application state: the setup hostname/SAN value,
/// the keys directory, the admin CIDRs collected at setup, and the rate
/// limits for the public auth routes.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// The setup hostname/SAN value (the default domain of the built-in
    /// profiles and the TOTP issuer context).
    pub domain: String,
    /// The keys directory: the JWT key pair, the CA keystore, and the
    /// secret-encryption key file all live under it.
    pub keys_dir: PathBuf,
    /// The admin CIDRs collected at setup (networks from which an
    /// operator reached the setup form).
    pub admin_cidrs: Vec<String>,
    /// The GCRA rate limit of the public auth routes (login, refresh,
    /// OIDC start/callback): per-token-bucket refill and burst, keyed on
    /// the peer IP. `None` disables the governor layer — TESTS ONLY —
    /// because axum's `ConnectInfo` (the peer IP) does not exist for an
    /// in-process `oneshot` request; the Task 13 binary always configures
    /// it.
    pub auth_rate_limit: Option<AuthRateLimit>,
    /// The ACME (RFC 8555) surface config: the public URL base and the
    /// optional ToS URL — see [`AcmeConfig`].
    pub acme: AcmeConfig,
}

impl ApiConfig {
    /// Build the config with the setup values and no rate limit (the test
    /// default); the binary sets `auth_rate_limit` explicitly. The ACME
    /// config starts UNCONFIGURED (an empty `public_url`): the ACME routes
    /// answer the problem document `serverInternal` under that config
    /// until the binary (or a test) carries a real value — see
    /// [`routes::acme`](crate::routes::acme).
    pub fn new(domain: String, keys_dir: PathBuf) -> Self {
        ApiConfig {
            domain,
            keys_dir,
            admin_cidrs: Vec::new(),
            auth_rate_limit: None,
            acme: AcmeConfig::unconfigured(),
        }
    }
}

/// The ACME (RFC 8555) deployment configuration: the absolute URL base
/// every ACME URL is built from (`WARDSTONE_PUBLIC_URL`, the settlement's
/// anti-Host-trust rule — the `Host` header is NEVER consulted) and the
/// optional terms-of-service URL (`WARDSTONE_ACME_TOS_URL`).
#[derive(Clone, Debug)]
pub struct AcmeConfig {
    /// The public base URL (`https://ca.example.test`): directory links,
    /// kid account URLs, and every `Location` header are built from it.
    /// An EMPTY value means "not configured": the ACME routes keep
    /// serving, but every one that would build an absolute URL answers
    /// the problem document `serverInternal` (the binary warns loudly at
    /// boot — the deployment choice: a misconfigured ACME env degrades the
    /// ACME surface alone, never the process).
    pub public_url: String,
    /// The terms-of-service document URL. `None` means the instance
    /// publishes no ToS: directories carry no `Link
    /// rel="terms-of-service"` header and new accounts are `valid`
    /// immediately. `Some` turns `termsOfServiceAgreed` into an enforced
    /// gate (the account is minted `pending` until the client agrees).
    pub tos_url: Option<String>,
}

impl AcmeConfig {
    /// The unconfigured default (the test/blank-env shape): an empty
    /// public URL and no ToS.
    pub fn unconfigured() -> Self {
        AcmeConfig {
            public_url: String::new(),
            tos_url: None,
        }
    }
}

/// The public auth routes' rate limit: one credit refilled every
/// `per_millis` milliseconds, `burst` credits held at most.
#[derive(Clone, Copy, Debug)]
pub struct AuthRateLimit {
    /// Refill period in milliseconds (house: one credit per 500 ms).
    pub per_millis: u64,
    /// Token-bucket burst size (house: 20 per IP on the auth routes).
    pub burst: u32,
}

/// The bounded, in-process access log. The middleware appends one line per
/// request — method, path, status, nothing else — and request/response
/// BODIES never reach it (the key-generation and CA-key-export responses
/// therefore cannot leak through logging). The Task 13 binary may mirror
/// the same lines to its real access log.
#[derive(Debug)]
pub struct AccessLog {
    entries: Mutex<VecDeque<String>>,
    cap: usize,
}

impl Default for AccessLog {
    fn default() -> Self {
        AccessLog {
            entries: Mutex::new(VecDeque::new()),
            cap: 512,
        }
    }
}

impl AccessLog {
    /// Append one line, dropping the oldest beyond the cap.
    pub fn push(&self, line: String) {
        if let Ok(mut entries) = self.entries.lock() {
            if entries.len() >= self.cap {
                entries.pop_front();
            }
            entries.push_back(line);
        }
    }

    /// A snapshot copy of the captured lines, oldest first.
    pub fn snapshot(&self) -> Vec<String> {
        self.entries
            .lock()
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// A pending OIDC csrf state: the tenant whose OAuth flow minted it, and
/// when it expires.
#[derive(Debug)]
struct OidcPending {
    tenant_id: uuid::Uuid,
    expires_at: Instant,
}

/// The in-memory OIDC csrf-state store (Task 3's R8 contract: `exchange_code`
/// deliberately does NOT re-validate `state` — ws-auth holds no session
/// store — so the API layer mints the state on the start route and
/// validates AND consumes it on the callback, before any code exchange).
///
/// The store is process-local on purpose: a csrf state must not survive a
/// restart or be shared between replicas (the binary is single-instance in
/// v1), and a lost store just means the operator retries the login.
#[derive(Debug, Default)]
pub struct OidcStateStore {
    states: Mutex<HashMap<String, OidcPending>>,
}

impl OidcStateStore {
    /// Mint a random state token, store it for `tenant_id`, and return its
    /// plaintext. 32 OS-entropy bytes, hex-encoded — the same size and
    /// encoding as every other bearer token in the workspace.
    pub fn mint(&self, tenant_id: uuid::Uuid) -> Result<String, ws_auth::error::AuthError> {
        use rand::{rngs::SysRng, TryRng};
        let mut raw = [0u8; 32];
        SysRng.try_fill_bytes(&mut raw).map_err(|e| {
            ws_auth::error::AuthError::Crypto(format!(
                "os entropy unavailable for the oidc csrf state: {e}"
            ))
        })?;
        let state = hex::encode(raw);
        if let Ok(mut states) = self.states.lock() {
            states.insert(
                state.clone(),
                OidcPending {
                    tenant_id,
                    expires_at: Instant::now() + OIDC_STATE_TTL,
                },
            );
            // Opportunistic gc: drop expired states while the lock is held.
            states.retain(|_, pending| pending.expires_at > Instant::now());
        }
        Ok(state)
    }

    /// Validate AND consume the state: `Some((tenant_id))` only when the
    /// state is known and unexpired, in which case it is removed — a
    /// replayed state validates once. The house's DashMap-removal check,
    /// here under one mutex.
    pub fn consume(&self, state: &str) -> Option<uuid::Uuid> {
        let mut states = self.states.lock().ok()?;
        let pending = states.remove(state)?;
        if pending.expires_at <= Instant::now() {
            return None;
        }
        Some(pending.tenant_id)
    }

    /// How many states are pending (observability; the Task 13 binary may
    /// expose it on `/api/v1/metrics`).
    pub fn pending_count(&self) -> usize {
        self.states.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// The pacing window between server-side verification attempts on one
/// authorization (settlement D5, the plan's Task-7 pin): a challenge POST
/// may run a verification per authorization per window; attempts inside
/// the window answer the `rateLimited` problem document without touching
/// the row. The counter lives in MEMORY ([`VerificationDeps`]): a restart
/// lifts the backoff — the accepted v1 shape, because the backoff paces a
/// retrying client, it is not a security boundary.
pub const CHALLENGE_ATTEMPT_BACKOFF: Duration = Duration::from_secs(5);

/// The challenge-verification seams (Plan 4 Task 7): the server-side
/// fetcher for HTTP-01, the TXT resolver for DNS-01, and the per-
/// authorization attempt pacing. Clonable: the fetcher/resolver fields
/// are `Arc` handles and the pacing map rides its own `Arc`, so every
/// clone shares one live set of seams and one pacing map.
#[derive(Clone)]
pub struct VerificationDeps {
    /// HTTP-01: GET the canonical fetch URL; the body is the exact-match
    /// input (`Ok`) or the failure detail (`Err`) the challenge error
    /// records.
    pub http_fetcher: Arc<dyn ChallengeFetch>,
    /// DNS-01: resolve the `_acme-challenge.<identifier>.` TXT name; the
    /// returned record strings are the any-match input.
    pub txt_resolver: Arc<dyn TxtResolver>,
    /// `authorization id -> the instant the NEXT attempt is allowed`;
    /// entries past their instant are stale and dropped opportunistically.
    attempts: Arc<Mutex<HashMap<uuid::Uuid, Instant>>>,
}

impl VerificationDeps {
    /// The production seams: the bounded reqwest fetcher (10s total per
    /// request, direct connections only — proxy environment variables are
    /// never trusted) and the hickory resolver over the system DNS
    /// configuration. A seam that cannot construct (an unreadable
    /// resolv.conf, a client build failure) degrades CLOSED — every
    /// verification attempt it serves fails, never a fake success.
    pub fn production() -> Self {
        let http_fetcher: Arc<dyn ChallengeFetch> = match Http01Fetcher::bounded() {
            Ok(fetcher) => Arc::new(fetcher),
            Err(err) => {
                tracing::error!(error = %err, "the HTTP-01 fetcher failed to construct");
                Arc::new(FailingFetcher(format!(
                    "the HTTP-01 fetcher is unavailable: {err}"
                )))
            }
        };
        let txt_resolver: Arc<dyn TxtResolver> = match TxtResolverHandle::from_system_conf() {
            Ok(resolver) => Arc::new(resolver),
            Err(err) => {
                tracing::error!(error = %err, "the DNS-01 resolver failed to construct");
                Arc::new(FailingTxtResolver(format!(
                    "the DNS-01 resolver is unavailable: {err}"
                )))
            }
        };
        Self::with_seams(http_fetcher, txt_resolver)
    }

    /// The injection constructor (tests and future alternate
    /// deployments): caller-supplied seam objects over an empty pacing
    /// map.
    pub fn with_seams(
        http_fetcher: Arc<dyn ChallengeFetch>,
        txt_resolver: Arc<dyn TxtResolver>,
    ) -> Self {
        VerificationDeps {
            http_fetcher,
            txt_resolver,
            attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The pacing gate: `true` when the attempt is allowed, spending the
    /// allowance atomically under one lock hold (the next attempt on this
    /// authorization inside [`CHALLENGE_ATTEMPT_BACKOFF`] is refused). A
    /// poisoned lock fails OPEN — only a panic while the lock was held
    /// poisons it, and pacing is not a security boundary — while
    /// opportunistic GC drops the stale entries the check walks over.
    pub fn try_record_attempt(&self, authorization_id: uuid::Uuid) -> bool {
        let Ok(mut attempts) = self.attempts.lock() else {
            tracing::warn!(
                "the challenge-attempt pacing map is poisoned; the attempt runs un-paced"
            );
            return true;
        };
        let now = Instant::now();
        if attempts
            .get(&authorization_id)
            .is_some_and(|next| *next > now)
        {
            return false;
        }
        attempts.retain(|_, next| *next > now);
        attempts.insert(authorization_id, now + CHALLENGE_ATTEMPT_BACKOFF);
        true
    }
}

/// The application state of the REST surface. Clonable (the pool and the
/// shared handles are cheap `Arc`/connection copies).
#[derive(Clone)]
pub struct AppState {
    /// The database pool (Task 2's migrated schema).
    pub pool: PgPool,
    /// The Ed25519 JWT key pair, loaded (or generated) at boot.
    pub jwt: Arc<JwtKeys>,
    /// The deployment configuration.
    pub config: ApiConfig,
    /// The bounded access log the middleware appends to.
    pub access_log: Arc<AccessLog>,
    /// The OIDC csrf-state store (Task 3's R8 contract).
    pub oidc_states: Arc<OidcStateStore>,
    /// The ACME anti-replay nonce ledger (Plan 4 Task 4's store): every
    /// `/acme` response mints a fresh `Replay-Nonce` from it and every
    /// ACME request spends one through `verify_jws` — single-use,
    /// in-memory (a restart simply re-nonces).
    pub nonces: Arc<NonceStore>,
    /// The challenge-verification seams (Plan 4 Task 7): the server-side
    /// HTTP-01 fetcher, the DNS-01 TXT resolver, and the per-authorization
    /// attempt pacing — the routes compute every expected answer from
    /// these; client-supplied data is never a verification input.
    pub verification: VerificationDeps,
}

impl AppState {
    /// Build the state from the pool, the JWT key pair, and the config;
    /// the mutable-by-product stores start empty.
    pub fn new(pool: PgPool, jwt: Arc<JwtKeys>, config: ApiConfig) -> Self {
        AppState {
            pool,
            jwt,
            config,
            access_log: Arc::new(AccessLog::default()),
            oidc_states: Arc::new(OidcStateStore::default()),
            nonces: Arc::new(NonceStore::new()),
            verification: VerificationDeps::production(),
        }
    }

    /// The path of the secret-encryption key file (the TOTP and OIDC
    /// client-secret envelope key under the keys directory).
    pub fn secret_key_path(&self) -> PathBuf {
        self.config.keys_dir.join(SECRET_KEY_FILE)
    }
}
