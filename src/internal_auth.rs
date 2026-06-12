use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{self, Request},
    http::{Method, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet},
};
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;

use crate::{models::InternalErrorResponse, state::State};

pub const SCOPE_BLINK_ACCOUNTS_CREATE: &str = "blink:accounts:create";
pub const SCOPE_ACCOUNTS_READ: &str = "accounts:read";
pub const SCOPE_SETTLEMENT_WRITE: &str = "settlement:write";
pub const SCOPE_TRANSFER_WRITE: &str = "transfer:write";

#[derive(Debug, Clone)]
pub struct InternalAuthState {
    keys: HashMap<String, DecodingKey>,
    issuer: String,
    audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalPrincipal {
    pub subject: Option<String>,
    pub scopes: HashSet<String>,
}

#[derive(Debug, Deserialize)]
pub struct InternalClaims {
    pub sub: Option<String>,
    pub scope: Option<Value>,
    pub scp: Option<Value>,
    pub scopes: Option<Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum InternalAuthError {
    #[error("invalid JWKS: {0}")]
    InvalidJwks(serde_json::Error),
    #[error("JWKS key missing kid")]
    MissingKid,
    #[error("invalid JWKS key: {0}")]
    InvalidKey(jsonwebtoken::errors::Error),
    #[error("missing bearer token")]
    MissingBearer,
    #[error("invalid token header: {0}")]
    InvalidHeader(jsonwebtoken::errors::Error),
    #[error("missing kid")]
    MissingTokenKid,
    #[error("unknown kid")]
    UnknownKid,
    #[error("unsupported alg")]
    UnsupportedAlgorithm,
    #[error("invalid token: {0}")]
    InvalidToken(jsonwebtoken::errors::Error),
}

impl InternalAuthState {
    pub fn from_jwks_json(
        jwks_json: &str,
        issuer: String,
        audience: String,
    ) -> Result<Self, InternalAuthError> {
        let jwks: JwkSet =
            serde_json::from_str(jwks_json).map_err(InternalAuthError::InvalidJwks)?;
        let mut keys = HashMap::new();
        for jwk in &jwks.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                return Err(InternalAuthError::MissingKid);
            };
            keys.insert(kid, decoding_key_from_jwk(jwk)?);
        }
        Ok(Self {
            keys,
            issuer,
            audience,
        })
    }
}

pub async fn internal_auth<DB>(
    extract::State(state): extract::State<State<DB>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode>
where
    DB: Send + Sync + 'static,
{
    if req.method() == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    let Some(auth_state) = state.internal_auth.as_ref() else {
        debug!("internal auth state unavailable; failing closed");
        return Err(StatusCode::UNAUTHORIZED);
    };
    let token = bearer_token(&req).map_err(|e| {
        debug!("invalid internal auth header: {e}");
        StatusCode::UNAUTHORIZED
    })?;
    let principal = validate_internal_token(auth_state, token).map_err(|e| {
        debug!("invalid internal JWT: {e}");
        StatusCode::UNAUTHORIZED
    })?;

    req.extensions_mut().insert(principal);
    Ok(next.run(req).await)
}

pub fn validate_internal_token(
    state: &InternalAuthState,
    token: &str,
) -> Result<InternalPrincipal, InternalAuthError> {
    let header = decode_header(token).map_err(InternalAuthError::InvalidHeader)?;
    if header.alg != Algorithm::RS256 {
        return Err(InternalAuthError::UnsupportedAlgorithm);
    }
    let kid = header.kid.ok_or(InternalAuthError::MissingTokenKid)?;
    let key = state.keys.get(&kid).ok_or(InternalAuthError::UnknownKid)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_nbf = true;
    validation.set_issuer(&[state.issuer.as_str()]);
    validation.set_audience(&[state.audience.as_str()]);
    validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud"]);

    let token_data = decode::<InternalClaims>(token, key, &validation)
        .map_err(InternalAuthError::InvalidToken)?;
    let scopes = parse_scopes(&token_data.claims);
    Ok(InternalPrincipal {
        subject: token_data.claims.sub,
        scopes,
    })
}

pub fn require_scope(
    principal: &InternalPrincipal,
    scope: &str,
) -> Result<(), (StatusCode, Json<InternalErrorResponse>)> {
    if principal.scopes.contains(scope) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(InternalErrorResponse::new("forbidden")),
        ))
    }
}

fn decoding_key_from_jwk(jwk: &Jwk) -> Result<DecodingKey, InternalAuthError> {
    DecodingKey::from_jwk(jwk).map_err(InternalAuthError::InvalidKey)
}

fn bearer_token(req: &Request) -> Result<&str, InternalAuthError> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(InternalAuthError::MissingBearer)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(InternalAuthError::MissingBearer)?;
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return Err(InternalAuthError::MissingBearer);
    }
    Ok(token)
}

fn parse_scopes(claims: &InternalClaims) -> HashSet<String> {
    let mut scopes = HashSet::new();
    extend_scopes(&mut scopes, claims.scope.as_ref(), ScopeShape::StringOnly);
    extend_scopes(&mut scopes, claims.scp.as_ref(), ScopeShape::StringOrArray);
    extend_scopes(
        &mut scopes,
        claims.scopes.as_ref(),
        ScopeShape::StringOrArray,
    );
    scopes
}

enum ScopeShape {
    StringOnly,
    StringOrArray,
}

fn extend_scopes(scopes: &mut HashSet<String>, value: Option<&Value>, shape: ScopeShape) {
    let Some(value) = value else {
        return;
    };
    match (value, shape) {
        (Value::String(scope_string), _) => scopes.extend(split_scope_string(scope_string)),
        (Value::Array(items), ScopeShape::StringOrArray) if items.iter().all(Value::is_string) => {
            scopes.extend(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string),
            );
        }
        _ => {}
    }
}

fn split_scope_string(scope_string: &str) -> impl Iterator<Item = String> + '_ {
    scope_string.split_whitespace().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use jsonwebtoken::{EncodingKey, Header, encode};

    const TEST_KID: &str = "blink-internal-test-key";
    const TEST_ISSUER: &str = "https://issuer.internal.test";
    const TEST_AUDIENCE: &str = "lnurl-server.internal.test";

    fn test_auth_state() -> InternalAuthState {
        InternalAuthState::from_jwks_json(
            include_str!("../tests/fixtures/internal_auth_jwks.json"),
            TEST_ISSUER.to_string(),
            TEST_AUDIENCE.to_string(),
        )
        .expect("test JWKS fixture must load")
    }

    fn test_token_with_header_and_claims(header: &Header, claims: &Value) -> String {
        encode(
            header,
            claims,
            &EncodingKey::from_rsa_pem(include_bytes!(
                "../tests/fixtures/internal_auth_private.pem"
            ))
            .expect("test RSA key must parse"),
        )
        .expect("test JWT must sign")
    }

    fn rs256_header(kid: Option<&str>) -> Header {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(ToString::to_string);
        header
    }

    fn valid_claims(scopes: &Value) -> Value {
        serde_json::json!({
            "sub": "blink-core-test-service",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": 4_102_444_800_u64,
            "nbf": 1_700_000_000_u64,
            "scope": scopes,
        })
    }

    fn valid_test_token() -> String {
        test_token_with_header_and_claims(
            &rs256_header(Some(TEST_KID)),
            &valid_claims(&Value::String(SCOPE_BLINK_ACCOUNTS_CREATE.to_string())),
        )
    }

    fn request_with_authorization(value: Option<&str>) -> Request {
        let mut builder = Request::builder().uri("/internal/blink/accounts");
        if let Some(value) = value {
            builder = builder.header(AUTHORIZATION, value);
        }
        builder.body(Body::empty()).expect("request builds")
    }

    #[test]
    fn internal_auth_scope_parser_accepts_compatible_d12_claim_shapes() {
        let claims: InternalClaims = serde_json::from_value(serde_json::json!({
            "scope": "blink:accounts:create accounts:read",
            "scp": ["settlement:write"],
            "scopes": "transfer:write"
        }))
        .expect("claims parse");
        let scopes = parse_scopes(&claims);
        assert!(scopes.contains(SCOPE_BLINK_ACCOUNTS_CREATE));
        assert!(scopes.contains(SCOPE_ACCOUNTS_READ));
        assert!(scopes.contains(SCOPE_SETTLEMENT_WRITE));
        assert!(scopes.contains(SCOPE_TRANSFER_WRITE));
    }

    #[test]
    fn internal_auth_accepts_scope_string_claim() {
        // D-12: OAuth-style `scope` strings are accepted for scoped authorization.
        let claims: InternalClaims = serde_json::from_value(serde_json::json!({
            "scope": "blink:accounts:create accounts:read"
        }))
        .expect("claims parse");

        let scopes = parse_scopes(&claims);

        assert!(scopes.contains(SCOPE_BLINK_ACCOUNTS_CREATE));
        assert!(scopes.contains(SCOPE_ACCOUNTS_READ));
    }

    #[test]
    fn internal_auth_accepts_scp_string_or_array_claim() {
        // D-12: `scp` supports whitespace-delimited strings or string arrays.
        for value in [
            serde_json::json!("blink:accounts:create accounts:read"),
            serde_json::json!(["blink:accounts:create", "accounts:read"]),
        ] {
            let claims: InternalClaims = serde_json::from_value(serde_json::json!({
                "scp": value
            }))
            .expect("claims parse");

            let scopes = parse_scopes(&claims);

            assert!(scopes.contains(SCOPE_BLINK_ACCOUNTS_CREATE));
            assert!(scopes.contains(SCOPE_ACCOUNTS_READ));
        }
    }

    #[test]
    fn internal_auth_accepts_scopes_string_or_array_claim() {
        // D-12: `scopes` supports whitespace-delimited strings or string arrays.
        for value in [
            serde_json::json!("blink:accounts:create accounts:read"),
            serde_json::json!(["blink:accounts:create", "accounts:read"]),
        ] {
            let claims: InternalClaims = serde_json::from_value(serde_json::json!({
                "scopes": value
            }))
            .expect("claims parse");

            let scopes = parse_scopes(&claims);

            assert!(scopes.contains(SCOPE_BLINK_ACCOUNTS_CREATE));
            assert!(scopes.contains(SCOPE_ACCOUNTS_READ));
        }
    }

    #[test]
    fn malformed_scope_claims_do_not_grant_authorization() {
        let claims: InternalClaims = serde_json::from_value(serde_json::json!({
            "scope": ["blink:accounts:create"],
            "scp": ["accounts:read", 5, true],
            "scopes": {"admin": true}
        }))
        .expect("claims parse");
        let scopes = parse_scopes(&claims);
        assert!(!scopes.contains(SCOPE_BLINK_ACCOUNTS_CREATE));
        assert!(!scopes.contains(SCOPE_ACCOUNTS_READ));
        assert!(scopes.is_empty());
    }

    #[test]
    fn internal_auth_malformed_scope_claim_values_do_not_grant_access() {
        // D-09/D-10/D-12: malformed non-string array members cannot grant scopes.
        let claims: InternalClaims = serde_json::from_value(serde_json::json!({
            "scope": ["blink:accounts:create"],
            "scp": ["accounts:read", 5],
            "scopes": {"admin": true}
        }))
        .expect("claims parse");

        let scopes = parse_scopes(&claims);

        assert!(scopes.is_empty());
    }

    #[test]
    fn internal_auth_rejects_missing_and_malformed_bearer_header() {
        // D-03/D-27: missing or malformed bearer headers fail closed before JWT parsing.
        let token = valid_test_token();

        for header in [
            None,
            Some(String::new()),
            Some("Basic abc".to_string()),
            Some("Bearer".to_string()),
            Some("Bearer ".to_string()),
            Some(format!("Bearer  {token}")),
        ] {
            let req = request_with_authorization(header.as_deref());

            assert!(matches!(
                bearer_token(&req),
                Err(InternalAuthError::MissingBearer)
            ));
        }
    }

    #[test]
    fn internal_auth_rejects_malformed_jwt() {
        // D-03/D-04: malformed JWTs return an invalid-header auth failure.
        let state = test_auth_state();

        assert!(matches!(
            validate_internal_token(&state, "not-a-jwt"),
            Err(InternalAuthError::InvalidHeader(_))
        ));
    }

    #[test]
    fn internal_auth_rejects_missing_kid_and_unknown_kid() {
        // D-03/D-04/D-07: key selection requires a matching configured `kid`.
        let state = test_auth_state();
        let missing_kid = test_token_with_header_and_claims(
            &rs256_header(None),
            &valid_claims(&serde_json::json!("accounts:read")),
        );
        let unknown_kid = test_token_with_header_and_claims(
            &rs256_header(Some("unknown-kid")),
            &valid_claims(&serde_json::json!("accounts:read")),
        );

        assert!(matches!(
            validate_internal_token(&state, &missing_kid),
            Err(InternalAuthError::MissingTokenKid)
        ));
        assert!(matches!(
            validate_internal_token(&state, &unknown_kid),
            Err(InternalAuthError::UnknownKid)
        ));
    }

    #[test]
    fn internal_auth_rejects_wrong_algorithm_and_invalid_signature() {
        // D-03/D-04/D-06: only RS256 tokens signed by the configured JWKS key are accepted.
        let state = test_auth_state();
        let mut hs_header = Header::new(Algorithm::HS256);
        hs_header.kid = Some(TEST_KID.to_string());
        let wrong_alg = encode(
            &hs_header,
            &valid_claims(&serde_json::json!("accounts:read")),
            &EncodingKey::from_secret(b"not-the-internal-secret"),
        )
        .expect("HS256 token signs for negative test");
        let mut invalid_signature = valid_test_token();
        invalid_signature.push('x');

        assert!(matches!(
            validate_internal_token(&state, &wrong_alg),
            Err(InternalAuthError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            validate_internal_token(&state, &invalid_signature),
            Err(InternalAuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn internal_auth_rejects_expired_nbf_issuer_and_audience_failures() {
        // D-03/D-04/D-06/D-27: temporal and configured iss/aud checks fail closed.
        let state = test_auth_state();
        let header = rs256_header(Some(TEST_KID));
        let cases = [
            serde_json::json!({
                "sub": "blink-core-test-service",
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
                "exp": 1_u64,
                "nbf": 1_u64,
                "scope": "accounts:read",
            }),
            serde_json::json!({
                "sub": "blink-core-test-service",
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
                "exp": 4_102_444_800_u64,
                "nbf": 4_102_444_000_u64,
                "scope": "accounts:read",
            }),
            serde_json::json!({
                "sub": "blink-core-test-service",
                "iss": "https://wrong-issuer.internal.test",
                "aud": TEST_AUDIENCE,
                "exp": 4_102_444_800_u64,
                "nbf": 1_700_000_000_u64,
                "scope": "accounts:read",
            }),
            serde_json::json!({
                "sub": "blink-core-test-service",
                "iss": TEST_ISSUER,
                "aud": "wrong-audience",
                "exp": 4_102_444_800_u64,
                "nbf": 1_700_000_000_u64,
                "scope": "accounts:read",
            }),
        ];

        for claims in cases {
            let token = test_token_with_header_and_claims(&header, &claims);

            assert!(matches!(
                validate_internal_token(&state, &token),
                Err(InternalAuthError::InvalidToken(_))
            ));
        }
    }

    #[test]
    fn internal_auth_jwks_source_failures_fail_closed() {
        // D-07/D-27: malformed local JWKS material is rejected deterministically.
        assert!(matches!(
            InternalAuthState::from_jwks_json(
                "not valid jwks",
                TEST_ISSUER.to_string(),
                TEST_AUDIENCE.to_string(),
            ),
            Err(InternalAuthError::InvalidJwks(_))
        ));
    }
}
