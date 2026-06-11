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
    header
        .strip_prefix("Bearer ")
        .filter(|token| !token.trim().is_empty())
        .map(str::trim)
        .ok_or(InternalAuthError::MissingBearer)
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
        (Value::Array(items), ScopeShape::StringOrArray) => {
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
        assert!(scopes.contains("settlement:write"));
        assert!(scopes.contains("transfer:write"));
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
        assert!(scopes.contains(SCOPE_ACCOUNTS_READ));
        assert_eq!(scopes.len(), 1);
    }
}
