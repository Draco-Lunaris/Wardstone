//! OIDC SSO tests: discovery fetch, authorization-code exchange, and — most
//! importantly — ID-token verification against the provider JWKS (an unverified
//! ID token is not an identity). The HTTP side is served by a throwaway
//! localhost server; the RS256 test keys are static, well below trusted-
//! key-strength, and used by test code only.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use serde_json::{json, Value};
use ws_auth::error::AuthError;
use ws_auth::oidc::{discover, exchange_code, identity_from_response, OidcConfig};

/// Static test-only RSA private key (PKCS#1 PEM). signs the success-path ID
/// token; its public half is served as the sole JWKS key (kid "test-key").
const KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3AHS+4fmiIkH+Mxg29F1a43tb713Yaq/Upptk2yT2zUig5nM
SIY187KG8s5al7unKcQcTx3xLVFKl3AyIgkdjbLEYj8nM9yCvLjM2g7EGe+73cS0
OGa7gzIZLmRuRHzY+bDnY4kzyyzaUhdCQy618lbBMtl7fcbOLG3ZKvVvSGvj2lxo
wALZntnv5ueb7mFyMmADQe2DrogxQUq7EIa1nmpmrJS24loKJ4ODazHg3LDML8KO
l3WXmY5a9NCtyy43Mlf6q+eg51EJaRxdVMJd0zpT1Fpi+JZg3ygSfn7S82Flup+1
Ec81RnIECy9Kv0LpEnN+y2sA/2ru0ETkEiNMqwIDAQABAoIBAATD+LfetbrO+AIU
RIJPRo4pcARBSszqky4kjtPoW3FvRWuyOwsy6NHzYUlcf1bpokxFg9afg9VyMwR7
Du8mpKjRFx6jyT47mnHJHUo0T604kWvuOtabZMCd6nQJHll/iSBGNHzmMt3Z5Fd7
touEUCLwUezn1iMOeyeJHB/6TTmGOS39EbxT1maSdLB8/Ecl7NgGNMP1XHY4Wwi3
OqOuV9jT3dSXvCRc09pKbvwQQu3+RKJFSJAOLIXB+bQHUB6jA2c+2Al7D5eILoxe
ontekw+OkC7bFxdjNsB64vnhdIhK2/Ttk05LzzA0Zag35bJKf//9jhzNZHjIeghb
lva6OQECgYEA/xNN1vRMHO7WRzzvngRyKxG0572yNwMtn+EQ8VM3Sayg3577W7L2
PskFhbjcWfs4wGVWaOWl9pe/RnnxzOi4d8SBsPMliwVgR+rOxU+qONme4FdEVruX
d72qmr+U4VydlM+xeogFSyAZDBfO+oEurzEepfYyTp5EZjKAHzzdxksCgYEA3M36
iR2WRz51HlGpwlJ5NQvYS68NebvVzgqCdL3uKeumiap0guEVF2u1m6M1P4RaEsFO
hFQTJBNan63TnS68mk8saKSSSJebc8r4MG5LpIiiJFdAe8oAMgDi23TECWtxPA5h
LvGrY3v+/yrAx5cl7CI8xwUIepiFz/RXNaC0FyECgYEAhir5Pp+xiWZ3f3El+NAN
3Wmq5lp5a0ZYsUgJSWakJjSPShCt1kYEEHJcXUInZY0nBMxI71QcP+EB02hBL68Z
mKXcMd8zWDSzuCBiMpb8ynptf0NnxtdVjL5PBqbPANteZ+/3QqRZZHK1ug6r6Ega
7jvACzu8qm3FPJxDmCrD3JECgYEAxw9fXXvx/jqdhX7jx09o/Fy4W8ruICAp6X3q
DGsqKlrLIfMs5M0coae16yEhISkltyDUs1HEi9Jy8d/ZFiyLVaYpCBHN22nqeGK0
i5zzztprKs4KUU9UC8BmxKgpD8DwLc9c5+BxvdeMlOgrMgTe6FoZZubvtO6KPGcw
tCU0FmECgYAn85o4FGbaKjiW3/81NFKsHDE/1kNvj8NnwGxjfptrOO8QRZnMKX9k
rjCyY0qjAs1wCKCxr+gbbMxtr4+d0XKEHzcqd89enwllgwcOGmT+9FRMuG8wSBRv
sKxv/JinmAtpweFhLjum/FvFZScWj9COQHsewyyBieBjsOwR4dBXJw==
-----END RSA PRIVATE KEY-----";

/// A second static key: signs the wrong-signature ID token. Its public half
/// is NOT in the JWKS, so verification must reject anything it signs.
const WRONG_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxiA9pxh/yccAQtd/xD86hKexwZ9cK0Cdnb1ubhVPfSjmHZgt
r/LTWjFH65YLqajQbFUSNDufTks0dPyV62j818zD3cMey23rT8ey/ZmiBwcWG8um
8gEphoFGzUNunwDFJ1GRt5Nnbw9LJeh1T4Grjie9J9q96t7YOdNhSVYShdNeWj/k
nxSuu9xtbp9tyhP7QFLbr0kjSCLLkSSvRzb2ecw90c61x2BduQXvYVSnCHqab8zW
zYnO19LiOYcvQzGTBKd+a1qsjUOa9v68Ny5ZfEnizDd8/uJI88JGlENQWw+0fQB5
vaLLMjHaGATdiu0PnoXMnnhHXKsl0axSwK0kuQIDAQABAoIBABMWtaH1ChDch8Go
5iI4DlEMICP90OFI8TaqsupPytAOAffNeu9mF6drsph35SlEPsqFOsMGEI/4TnZM
BLzA6YV4MNHbtAqZDVArNytYY0RGkkJ80VmlM4VGTNZHfi+7IQOsB/xWKyPH5y9g
kXbm0SrZ2M9vc5dev5n4q/mnHZM/kdFXVu0IeHcGePsxo42Cf0ynCnUosgp+h+uS
3uY1TapxleJH5KbSRKD5MZD7LKLbmTlRHl/jrKTSaNU3CeM7fUPTmjxMCyQxzRHY
orMKrEYgEi8YG1bhhgnFSZ3gySoSAJsEe5eo8DbMRFV+jmrOlV73YnMSzoufTcK1
DaSPxcUCgYEA9+3/iOuLvVD7JRBQ50FYB1eQv5dArxBXyw6Is6RiqeqwwukN6jpj
nFacJP5gnjRZNRvFOi+ps4lb2JzAOmG19OLJEFK4jC7IK9YeuzJqzQhiIXyWpJXo
rlm1bETtdvsgkd+T8O432rImxEXlYUQInfa8E3KiZcbskPG+CBI6pmUCgYEAzJM6
MegK54ZugSw9uwqsVMLJLhjboq7TL1+4X9sN9OUCG2epk6SglRn4P2hOKt0FKg63
pIW1rUW5y7pwkziyQorhlGx8UogaI9LUxYtu7qqveo5yx+OiSYinctjXdDR5pNv1
UqDp1a5vhpTGgb7j3oB1+X6npZ/YiLDogqBcpcUCgYEAvpj6j3n1DW9KAy5N49o6
IDrTDlbq5Sp9M59SvDetmc7QYKbliaGlnjR/CXl9MWIxCkD1GEw3+8unDhlDNh6T
0VTfGWtecHYucHTFX0fdDw5Y0kGDVbfhDtfsPvWmUIeyfDIS+29HBRtb7huFwYaZ
0UYzRAgmjHOmva76Vh4ddHkCgYEAwnLqrMcnnjvcS3GW13NkrEhdWzCLi81qtKvi
H1KiqHUIlK3qtIiVjkOaAAMP0ZQ1tW05xurE7gbJfEkhef45CiDiG+cmIHh3iDd8
wKww7DBXDUHa/f5zojt/Fh3gZPb/7OCaBUkoGlBsd1pweKDODQ7DlDt79GTEN+EX
kBoHFhUCgYEAqPuU3S26y5XaSmrk94gooaICgpXlV3R9y/FKPQO/u87x+ee82TTJ
h9/8kYQCUfdoudhddH5bpb06/dC1GQQXznTnPJNxz1GGWSl28KCx9o7ReAMQPE6x
s5qSMVuU7PE2S4vmXcUKd0yEIs4QOz1KbSY9rB97auV7OhO7K38yyGI=
-----END RSA PRIVATE KEY-----";

/// base64url(unpadded) modulus of KEY_PEM.
const KEY_N_B64URL: &str = "3AHS-4fmiIkH-Mxg29F1a43tb713Yaq_Upptk2yT2zUig5nMSIY187KG8s5al7unKcQcTx3xLVFKl3AyIgkdjbLEYj8nM9yCvLjM2g7EGe-73cS0OGa7gzIZLmRuRHzY-bDnY4kzyyzaUhdCQy618lbBMtl7fcbOLG3ZKvVvSGvj2lxowALZntnv5ueb7mFyMmADQe2DrogxQUq7EIa1nmpmrJS24loKJ4ODazHg3LDML8KOl3WXmY5a9NCtyy43Mlf6q-eg51EJaRxdVMJd0zpT1Fpi-JZg3ygSfn7S82Flup-1Ec81RnIECy9Kv0LpEnN-y2sA_2ru0ETkEiNMqw";

/// base64url modulus of WRONG_KEY_PEM (a JWKS key that does not verify).
const WRONG_KEY_N_B64URL: &str = "xiA9pxh_yccAQtd_xD86hKexwZ9cK0Cdnb1ubhVPfSjmHZgtr_LTWjFH65YLqajQbFUSNDufTks0dPyV62j818zD3cMey23rT8ey_ZmiBwcWG8um8gEphoFGzUNunwDFJ1GRt5Nnbw9LJeh1T4Grjie9J9q96t7YOdNhSVYShdNeWj_knxSuu9xtbp9tyhP7QFLbr0kjSCLLkSSvRzb2ecw90c61x2BduQXvYVSnCHqab8zWzYnO19LiOYcvQzGTBKd-a1qsjUOa9v68Ny5ZfEnizDd8_uJI88JGlENQWw-0fQB5vaLLMjHaGATdiu0PnoXMnnhHXKsl0axSwK0kuQ";

/// RSA public exponent 65537 = 0x010001, base64url unpadded.
const KEY_E_B64URL: &str = "AQAB";

const TEST_KID: &str = "test-key";

fn test_config(discovery_url: &str) -> OidcConfig {
    let mem = ws_secmem::global().expect("the protected pool initializes");
    OidcConfig {
        provider_type: "keycloak".to_string(),
        display_name: "Test Provider".to_string(),
        discovery_url: discovery_url.to_string(),
        client_id: "wardstone-client".to_string(),
        client_secret: mem
            .alloc_copy(b"swordfish")
            .expect("the arena holds the test client secret"),
        redirect_uri: "http://localhost:8443/api/v1/auth/sso/callback".to_string(),
        scopes: "openid profile email".to_string(),
    }
}

fn jwks_for(n_b64url: &str) -> Value {
    json!({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": TEST_KID,
                "alg": "RS256",
                "n": n_b64url,
                "e": KEY_E_B64URL,
            }
        ]
    })
}

/// Sign `claims` as an RS256 JWT with the given key and kid.
fn sign_token(key_pem: &str, kid: &str, claims: Value) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(key_pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn id_token_claims(issuer: &str, audience: &str) -> Value {
    let now = chrono::Utc::now();
    json!({
        "iss": issuer,
        "aud": audience,
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
        "sub": "user-12345",
        "email": "alice@example.test",
        "name": "Alice Example",
        "preferred_username": "alice",
    })
}

/// Serve `discovery_doc`'s relative paths on a localhost listener until the
/// test process ends. Returns the base URL ("http://127.0.0.1:port") and
/// the captured BODIES of every token-endpoint POST — the exchange tests
/// assert the confidential secret travels to the token endpoint and a
/// public client's does not.
fn spawn_server(config: &OidcConfig) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    // The discovery document points back at this server's /jwks and /token.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let discovery = json!({
        "issuer": format!("http://127.0.0.1:{port}"),
        "authorization_endpoint": format!("http://127.0.0.1:{port}/authorize"),
        "token_endpoint": format!("http://127.0.0.1:{port}/token"),
        "jwks_uri": format!("http://127.0.0.1:{port}/jwks"),
    });
    let jwks = jwks_for(KEY_N_B64URL).to_string();
    // Token response: the caller-sent code mirrored back into a signed ID token.
    let token_prefix = config.client_id.clone();
    let token_bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = std::sync::Arc::clone(&token_bodies);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let request = read_request(&mut stream);
            let first_line = request.lines().next().unwrap_or_default();
            let path = first_line.split_whitespace().nth(1).unwrap_or("/");
            let (status, body) = if path.starts_with("/discovery") {
                ("200 OK", discovery.to_string())
            } else if path.starts_with("/jwks") {
                ("200 OK", jwks.clone())
            } else if path.starts_with("/token") {
                captured
                    .lock()
                    .expect("the token-body capture lock")
                    .push(request_body(&request).to_string());
                let signed = sign_token(
                    KEY_PEM,
                    TEST_KID,
                    id_token_claims(&format!("http://127.0.0.1:{port}"), &token_prefix),
                );
                (
                    "200 OK",
                    json!({
                        "access_token": "at-xyz",
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "id_token": signed,
                    })
                    .to_string(),
                )
            } else {
                ("404 Not Found", r#"{"error":"not_found"}"#.to_string())
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    (format!("http://127.0.0.1:{port}"), token_bodies)
}

/// Read one HTTP request off `stream` — the header block, then exactly
/// `Content-Length` bytes of body — so the token-endpoint capture sees
/// the whole form body (a single read is not guaranteed to carry it).
fn read_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    let body_start = loop {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            return String::from_utf8_lossy(&request).into_owned();
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let headers = String::from_utf8_lossy(&request[..body_start]).to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    while request.len() < body_start + content_length {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&request).into_owned()
}

/// The body half of a captured request (empty when there was none).
fn request_body(request: &str) -> &str {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

#[tokio::test]
async fn discovery_fetches_the_provider_document() {
    let (base, _token_bodies) = spawn_server(&test_config(""));
    let config = test_config(&format!("{base}/discovery"));
    let disc = discover(&config).await.unwrap();
    assert!(disc.authorization_endpoint.ends_with("/authorize"));
    assert!(disc.token_endpoint.ends_with("/token"));
    assert!(disc.jwks_uri.ends_with("/jwks"));
    assert!(disc.issuer.starts_with("http://127.0.0.1:"));
}

#[tokio::test]
async fn discovery_of_an_unreachable_provider_is_a_config_error() {
    // Bind, read the port, drop: nothing listens there anymore.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let config = test_config(&format!("http://127.0.0.1:{port}/discovery"));
    let err = discover(&config).await.unwrap_err();
    assert!(matches!(err, AuthError::Config(_)), "got: {err:?}");
}

#[tokio::test]
async fn exchange_code_yields_a_verified_identity() {
    let config = test_config("PLACEHOLDER");
    let (base, _token_bodies) = spawn_server(&config);
    let config = test_config(&format!("{base}/discovery"));
    let disc = discover(&config).await.unwrap();
    let identity = exchange_code(&config, &disc, "the-auth-code", "the-state")
        .await
        .unwrap();
    // Claims come from the signed (and signature-verified) ID token.
    assert_eq!(identity.subject, "user-12345");
    assert_eq!(identity.email.as_deref(), Some("alice@example.test"));
    assert_eq!(identity.display_name.as_deref(), Some("Alice Example"));
}

#[tokio::test]
async fn exchange_code_rejects_provider_side_rejection() {
    let config = test_config("PLACEHOLDER");
    let (base, _token_bodies) = spawn_server(&config);
    // Point the token endpoint at the 404 path: the provider never grants.
    let disc = ws_auth::oidc::OidcDiscovery {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/no-such-token"),
        jwks_uri: format!("{base}/jwks"),
    };
    let err = exchange_code(&config, &disc, "the-auth-code", "s")
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::BadCredentials), "got: {err:?}");
}

/// The exchange path receives the client secret: a confidential client's
/// token POST carries the opened secret in its form body, and a PUBLIC
/// client's POST omits the parameter outright (the house omission rule —
/// never an empty credential).
#[tokio::test]
async fn exchange_code_carries_the_confidential_secret_and_omits_it_for_public_clients() {
    // The confidential arm.
    let config = test_config("PLACEHOLDER");
    let (base, token_bodies) = spawn_server(&config);
    let config = test_config(&format!("{base}/discovery"));
    let disc = discover(&config).await.unwrap();
    let identity = exchange_code(&config, &disc, "the-auth-code", "the-state")
        .await
        .unwrap();
    assert_eq!(identity.subject, "user-12345");
    let confidential = token_bodies
        .lock()
        .expect("the token-body capture lock")
        .clone();
    assert_eq!(confidential.len(), 1, "one token POST for the exchange");
    assert!(
        confidential[0].contains("client_secret=swordfish"),
        "the confidential exchange carries the opened secret: {}",
        confidential[0]
    );

    // The public arm: an EMPTY arena buffer — the absent-pair convention
    // the API layer hands a public client — omits the parameter.
    let mem = ws_secmem::global().expect("the protected pool initializes");
    let mut public = test_config(&format!("{base}/discovery"));
    public.client_secret = mem
        .alloc(0)
        .expect("the arena serves the empty public-client buffer");
    let disc = discover(&public).await.unwrap();
    let identity = exchange_code(&public, &disc, "the-auth-code", "the-state")
        .await
        .unwrap();
    assert_eq!(identity.subject, "user-12345");
    let bodies = token_bodies
        .lock()
        .expect("the token-body capture lock")
        .clone();
    assert_eq!(bodies.len(), 2, "the public exchange made its own POST");
    assert!(
        !bodies[1].contains("client_secret"),
        "the public client's POST omits the secret parameter: {}",
        bodies[1]
    );
}

#[tokio::test]
async fn identity_from_response_maps_verified_claims() {
    let config = test_config("");
    let issuer = "https://idp.example.test/realms/wardstone";
    let token = sign_token(
        KEY_PEM,
        TEST_KID,
        id_token_claims(issuer, &config.client_id),
    );
    let identity = identity_from_response(&config, issuer, &token, &jwks_for(KEY_N_B64URL))
        .await
        .unwrap();
    assert_eq!(identity.subject, "user-12345");
    assert_eq!(identity.email.as_deref(), Some("alice@example.test"));
    assert_eq!(identity.display_name.as_deref(), Some("Alice Example"));
}

#[tokio::test]
async fn identity_from_response_rejects_a_wrong_signature() {
    let config = test_config("");
    let issuer = "https://idp.example.test/realms/wardstone";
    // Signed by a key that is NOT in the JWKS: must be an error, not a
    // best-effort identity from an unsigned body.
    let token = sign_token(
        WRONG_KEY_PEM,
        TEST_KID,
        id_token_claims(issuer, &config.client_id),
    );
    let err = identity_from_response(&config, issuer, &token, &jwks_for(KEY_N_B64URL))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::TokenInvalid), "got: {err:?}");
}

#[tokio::test]
async fn identity_from_response_rejects_a_wrong_audience() {
    let config = test_config("");
    let issuer = "https://idp.example.test/realms/wardstone";
    let token = sign_token(
        KEY_PEM,
        TEST_KID,
        id_token_claims(issuer, "some-other-client"),
    );
    let err = identity_from_response(&config, issuer, &token, &jwks_for(KEY_N_B64URL))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::TokenInvalid), "got: {err:?}");
}

#[tokio::test]
async fn identity_from_response_requires_a_subject() {
    let config = test_config("");
    let issuer = "https://idp.example.test/realms/wardstone";
    let mut claims = id_token_claims(issuer, &config.client_id);
    claims["sub"] = Value::Null;
    let token = sign_token(KEY_PEM, TEST_KID, claims);
    let err = identity_from_response(&config, issuer, &token, &jwks_for(KEY_N_B64URL))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::TokenInvalid), "got: {err:?}");
}

#[tokio::test]
async fn identity_from_response_rejects_a_missing_kid() {
    let config = test_config("");
    let issuer = "https://idp.example.test/realms/wardstone";
    let token = sign_token(KEY_PEM, "", id_token_claims(issuer, &config.client_id));
    let err = identity_from_response(&config, issuer, &token, &jwks_for(KEY_N_B64URL))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::TokenInvalid), "got: {err:?}");
}

/// The house's Azure-oid claim (pm-web sso.rs `oid`) is a subject fallback:
/// a token with no `sub` but a provider `oid` still yields an identity.
#[tokio::test]
async fn identity_from_azure_style_oid_claim() {
    let config = test_config("");
    let issuer = "https://login.microsoftonline.com/tenant/v2.0";
    let mut claims = id_token_claims(issuer, &config.client_id);
    claims["sub"] = Value::Null;
    claims["oid"] = json!("00000000-0000-0000-0000-000000000001");
    let token = sign_token(KEY_PEM, TEST_KID, claims);
    let identity = identity_from_response(&config, issuer, &token, &jwks_for(KEY_N_B64URL))
        .await
        .unwrap();
    assert_eq!(identity.subject, "00000000-0000-0000-0000-000000000001");
}
/// A JWKS whose sole key carries the expected kid but a DIFFERENT public key
/// — the stale/rotated-JWKS case. The signature cannot verify.
#[tokio::test]
async fn identity_from_response_rejects_a_stale_jwks_key() {
    let config = test_config("");
    let issuer = "https://idp.example.test/realms/wardstone";
    let token = sign_token(
        KEY_PEM,
        TEST_KID,
        id_token_claims(issuer, &config.client_id),
    );
    let err = identity_from_response(&config, issuer, &token, &jwks_for(WRONG_KEY_N_B64URL))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::TokenInvalid), "got: {err:?}");
}
