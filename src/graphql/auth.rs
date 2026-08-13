//! Auth for the federated subgraph. Validates the gateway-minted (Oathkeeper
//! `id_token`) JWT that Apollo Router forwards to subgraphs: issuer `galoy.io`,
//! RS256, `exp`/`nbf` — with **no audience claim** (the supergraph token
//! carries none; the `/lnurl-internal` REST token is a different, privileged
//! boundary and is not reused here).

use std::collections::{HashMap, HashSet};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct GatewayAuthState {
    keys: HashMap<String, DecodingKey>,
    issuer: String,
}

/// The authenticated (or anonymous) subject of a GraphQL request.
#[derive(Debug, Clone)]
pub struct AuthSubject {
    /// User/service id (`sub`). `None` for the signed anonymous gateway path.
    pub subject: Option<String>,
    /// OAuth scopes granted to the caller (e.g. `read`, `write`, `receive`).
    pub scopes: HashSet<String>,
}

impl AuthSubject {
    pub fn is_anonymous(&self) -> bool {
        self.subject.as_deref() == Some("anon") || self.subject.is_none()
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }
}

#[derive(Debug, Deserialize)]
pub struct GatewayClaims {
    pub sub: Option<String>,
    pub scope: Option<Value>,
    pub scp: Option<Value>,
    pub scopes: Option<Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayAuthError {
    #[error("invalid JWKS: {0}")]
    InvalidJwks(serde_json::Error),
    #[error("JWKS key missing kid")]
    MissingKid,
    #[error("invalid JWKS key: {0}")]
    InvalidKey(jsonwebtoken::errors::Error),
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

impl GatewayAuthState {
    pub fn from_jwks_json(jwks_json: &str, issuer: String) -> Result<Self, GatewayAuthError> {
        let jwks: JwkSet =
            serde_json::from_str(jwks_json).map_err(GatewayAuthError::InvalidJwks)?;
        let mut keys = HashMap::new();
        for jwk in &jwks.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                return Err(GatewayAuthError::MissingKid);
            };
            keys.insert(
                kid,
                DecodingKey::from_jwk(jwk).map_err(GatewayAuthError::InvalidKey)?,
            );
        }
        Ok(Self { keys, issuer })
    }
}

/// Validate a gateway JWT. Unlike the internal token path, this does not
/// require an `aud` claim, because the gateway token has none.
pub fn validate_gateway_token(
    state: &GatewayAuthState,
    token: &str,
) -> Result<AuthSubject, GatewayAuthError> {
    let header = decode_header(token).map_err(GatewayAuthError::InvalidHeader)?;
    if header.alg != Algorithm::RS256 {
        return Err(GatewayAuthError::UnsupportedAlgorithm);
    }
    let kid = header.kid.ok_or(GatewayAuthError::MissingTokenKid)?;
    let key = state.keys.get(&kid).ok_or(GatewayAuthError::UnknownKid)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_nbf = true;
    validation.set_issuer(&[state.issuer.as_str()]);
    // No audience validation: the gateway id_token has no `aud` claim.
    validation.set_required_spec_claims(&["exp", "nbf", "iss"]);

    let token_data =
        decode::<GatewayClaims>(token, key, &validation).map_err(GatewayAuthError::InvalidToken)?;
    let scopes = parse_scopes(&token_data.claims);
    Ok(AuthSubject {
        subject: token_data.claims.sub,
        scopes,
    })
}

fn parse_scopes(claims: &GatewayClaims) -> HashSet<String> {
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
    use jsonwebtoken::{EncodingKey, Header, encode};

    const TEST_KID: &str = "blink-internal-test-key";
    const GATEWAY_ISSUER: &str = "galoy.io";

    fn test_state() -> GatewayAuthState {
        GatewayAuthState::from_jwks_json(
            include_str!("../../tests/fixtures/internal_auth_jwks.json"),
            GATEWAY_ISSUER.to_string(),
        )
        .expect("fixture JWKS must load")
    }

    fn sign(claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(include_bytes!(
                "../../tests/fixtures/internal_auth_private.pem"
            ))
            .expect("test RSA key parses"),
        )
        .expect("token signs")
    }

    fn gateway_claims(sub: &str, scope: &str) -> Value {
        // Gateway id_token: issuer galoy.io, exp/nbf, NO aud claim.
        serde_json::json!({
            "sub": sub,
            "iss": GATEWAY_ISSUER,
            "exp": 4_102_444_800_u64,
            "nbf": 1_700_000_000_u64,
            "scope": scope,
        })
    }

    #[test]
    fn accepts_gateway_token_without_audience() {
        let state = test_state();
        let token = sign(&gateway_claims("user-123", "receive"));
        let subject = validate_gateway_token(&state, &token).expect("valid gateway token");
        assert_eq!(subject.subject.as_deref(), Some("user-123"));
        assert!(subject.has_scope("receive"));
    }

    #[test]
    fn accepts_anonymous_gateway_subject() {
        let state = test_state();
        let token = sign(&gateway_claims("anon", ""));
        let subject = validate_gateway_token(&state, &token).expect("anon gateway token");
        assert!(subject.is_anonymous());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let state = test_state();
        let mut claims = gateway_claims("user-123", "receive");
        claims["iss"] = Value::String("https://evil.example".to_string());
        let token = sign(&claims);
        assert!(matches!(
            validate_gateway_token(&state, &token),
            Err(GatewayAuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn rejects_expired_token() {
        let state = test_state();
        let mut claims = gateway_claims("user-123", "receive");
        claims["exp"] = Value::from(1_u64);
        let token = sign(&claims);
        assert!(matches!(
            validate_gateway_token(&state, &token),
            Err(GatewayAuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn parses_scope_variants() {
        let claims: GatewayClaims = serde_json::from_value(serde_json::json!({
            "scope": "read write",
            "scp": ["receive"]
        }))
        .expect("claims parse");
        let scopes = parse_scopes(&claims);
        assert!(scopes.contains("read"));
        assert!(scopes.contains("write"));
        assert!(scopes.contains("receive"));
    }
}
